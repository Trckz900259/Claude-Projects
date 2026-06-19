"""
governance.py — the data-governance layer.

Bug-bounty work means handling other people's secrets: captured tokens, session
cookies, auth headers, API keys. This module is the single place that decides
how that sensitive data is treated, so the rest of the platform never has to.

It does four jobs, each as a small self-contained class/function:

  1. Redactor       — scrub secrets out of any text/dict BEFORE it hits a log,
                      a report, or your terminal. Idempotent and conservative.
  2. FieldCipher    — encrypt individual datastore fields at rest (Fernet).
  3. SecretsStore   — resolve secrets from the environment or a gitignored file,
                      so credentials never live in code or in version control.
  4. RetentionPolicy— decide when captured data is too old to keep, and purge it.

Design goals (read these if you are new to the codebase):

  * Standalone. This file imports ONLY the standard library plus `cryptography`.
    It deliberately does not depend on any other ``core/*`` module, so it can be
    imported from anywhere (logging, datastore, CLI) without circular imports.
  * Safe by default. Redaction never raises on weird input; it only ever removes
    information, it never invents it. Decryption is forgiving so it can be run
    over data that may or may not already be encrypted.
  * Beginner-friendly. Every public method has a docstring and an example.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

# PyYAML is used elsewhere in the project, but we must not *require* it here:
# the secrets file is intentionally simple ("KEY: value" lines), so we fall back
# to a tiny parser when PyYAML is unavailable.
try:
    import yaml

    _HAVE_YAML = True
except Exception:  # pragma: no cover - yaml is normally installed
    _HAVE_YAML = False


# ===========================================================================
# 1. Redactor — keep secrets out of logs/reports
# ===========================================================================
class Redactor:
    """
    Replace secrets in text (or nested dicts) with short ``[REDACTED:...]`` tags.

    The point is leak-prevention: anything that *looks* like a credential is
    masked before it can be written to a log file, a report, or the screen.
    We err on the side of caution — a false positive only costs you a masked
    string, while a false negative could publish someone's token.

    Two important properties:

      * **Idempotent** — redacting already-redacted text changes nothing, so it
        is safe to run the same string through more than once.
      * **Non-destructive to normal text** — ordinary words, URLs, and numbers
        are left alone; only high-signal secret shapes are touched.

    Example::

        r = Redactor()
        r.redact("Authorization: Bearer eyJhbG.payload.sig")
        # -> 'Authorization: Bearer [REDACTED:bearer]'
    """

    # A token already produced by THIS redactor, e.g. "[REDACTED:jwt]". We skip
    # over these so a second pass is a no-op (idempotency).
    _TAG_RE = re.compile(r"\[REDACTED:[a-z0-9_]+\]")

    # Characters that make up the value side of a key=value secret. We stop at
    # whitespace, quotes, and common separators so we don't eat the rest of a
    # line / JSON object.
    _VALUE_CHARS = r"[^\s\"'&;,}\]]+"

    # The sensitive key=value names we mask the value of. Matched case-insensitively.
    _SENSITIVE_KV_KEYS = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
        "auth",
        "session",
        "client_secret",
    )

    def __init__(self) -> None:
        # Each rule is (compiled_regex, replacement). ``replacement`` may be a
        # plain string or a function (for rules that must preserve a prefix such
        # as "Bearer "). Order matters: more specific patterns come first.
        kv_keys = "|".join(re.escape(k) for k in self._SENSITIVE_KV_KEYS)

        self._rules: list[tuple[re.Pattern[str], object]] = [
            # --- Private key blocks (PEM). Match the whole BEGIN..END block. ---
            (
                re.compile(
                    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
                    r".*?"
                    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
                    re.DOTALL,
                ),
                "[REDACTED:private_key]",
            ),
            # --- Authorization: Bearer <token> (keep the scheme, mask token) ---
            (
                re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._\-+/=]+)"),
                lambda m: f"{m.group(1)}[REDACTED:bearer]",
            ),
            # --- Authorization: Basic <base64> (keep the scheme, mask creds) ---
            (
                re.compile(r"(?i)(Basic\s+)([A-Za-z0-9+/=]{8,})"),
                lambda m: f"{m.group(1)}[REDACTED:basic]",
            ),
            # --- JWT: three base64url segments separated by dots, starting eyJ ---
            (
                re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
                "[REDACTED:jwt]",
            ),
            # --- AWS access key id: AKIA/ASIA + 16 uppercase alphanumerics. ---
            # \b at the end stops it bleeding into longer tokens.
            (
                re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
                "[REDACTED:aws_key]",
            ),
            # --- key=value secrets (password=..., token=..., api_key=...). ---
            # Group 1 keeps "key=" (or "key: ") so we only mask the value.
            (
                re.compile(
                    rf"(?i)\b({kv_keys})(\s*[:=]\s*)(\"?)({self._VALUE_CHARS})",
                ),
                self._mask_kv,
            ),
            # --- Generic high-entropy tokens: long hex or base64-ish blobs. ---
            # 64+ hex chars (e.g. SHA-256 secrets, long API keys).
            (
                re.compile(r"\b[0-9a-fA-F]{64,}\b"),
                "[REDACTED:hex]",
            ),
            # 32+ char base64url-ish blob that contains a mix of cases/digits
            # (a heuristic for "this is probably a key, not an English word").
            (
                re.compile(r"\b(?=[A-Za-z0-9_\-+/]*[A-Z])(?=[A-Za-z0-9_\-+/]*[0-9])[A-Za-z0-9_\-+/]{32,}={0,2}\b"),
                "[REDACTED:token]",
            ),
        ]

    # -- helpers -----------------------------------------------------------
    def _mask_kv(self, m: re.Match[str]) -> str:
        """Replacement for key=value rule: keep ``key=`` and the opening quote,
        replace the value with a tag named after the key.

        Two cases are left untouched so we stay correct and idempotent:
          * the value is already a ``[REDACTED:...]`` tag (don't double-redact);
          * the value is an auth *scheme* word ("Bearer"/"Basic") — the bearer/
            basic rules (which run earlier) own those; masking the scheme word
            here would wrongly delete it.
        """
        key = m.group(1).lower()
        sep = m.group(2)
        quote = m.group(3) or ""
        value = m.group(4)
        if value.startswith("[REDACTED") or value.lower() in ("bearer", "basic"):
            return m.group(0)
        tag = self._kv_tag(key)
        return f"{key}{sep}{quote}[REDACTED:{tag}]"

    @staticmethod
    def _kv_tag(key: str) -> str:
        """Normalise a key name into a short tag label."""
        key = key.lower()
        if "password" in key or key in ("passwd", "pwd"):
            return "password"
        if "secret" in key:
            return "secret"
        if "api" in key:
            return "api_key"
        if "token" in key:
            return "token"
        return "secret"

    def _is_inside_existing_tag(self, text: str, start: int) -> bool:
        """True if position ``start`` falls within an existing [REDACTED:..] tag,
        so we don't re-redact (and thereby corrupt) our own output."""
        for tag in self._TAG_RE.finditer(text):
            if tag.start() <= start < tag.end():
                return True
        return False

    # -- public API --------------------------------------------------------
    def redact(self, text: str) -> str:
        """
        Return ``text`` with any detected secrets replaced by ``[REDACTED:...]``.

        Safe on any input (including the empty string and non-secret prose) and
        idempotent: ``redact(redact(x)) == redact(x)``.
        """
        if not text:
            return text
        if not isinstance(text, str):
            # Be forgiving: stringify so callers can pass us anything.
            text = str(text)

        for pattern, replacement in self._rules:

            def _sub(m: re.Match[str], _repl=replacement) -> str:
                # Idempotency guard: if this match overlaps an existing tag we
                # already wrote, leave it untouched.
                if self._is_inside_existing_tag(m.string, m.start()):
                    return m.group(0)
                if callable(_repl):
                    return _repl(m)  # type: ignore[operator]
                return _repl  # type: ignore[return-value]

            text = pattern.sub(_sub, text)

        return text

    def redact_dict(self, d: dict) -> dict:
        """
        Recursively redact a dict, returning a NEW dict (the input is untouched).

        Two layers of protection are applied:

          * If a key *name* looks sensitive (password/secret/token/key/
            authorization/cookie/...), its whole value is masked, whatever it is.
          * Otherwise, string values are passed through :meth:`redact`, and
            nested dicts/lists are walked recursively.
        """
        return self._redact_obj(d)  # type: ignore[return-value]

    def _redact_obj(self, obj):
        """Internal recursive worker used by :meth:`redact_dict`."""
        if isinstance(obj, dict):
            out: dict = {}
            for key, value in obj.items():
                if isinstance(key, str) and self._is_sensitive_key(key):
                    out[key] = "[REDACTED]"
                else:
                    out[key] = self._redact_obj(value)
            return out
        if isinstance(obj, (list, tuple)):
            redacted = [self._redact_obj(v) for v in obj]
            return type(obj)(redacted) if isinstance(obj, tuple) else redacted
        if isinstance(obj, str):
            return self.redact(obj)
        # Numbers, bools, None, etc. carry no secrets — pass through unchanged.
        return obj

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """Heuristic: does this dict-key NAME suggest the value is a secret?"""
        k = key.lower()
        needles = (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "credential",
            "private_key",
            "client_secret",
            "session",
        )
        if any(n in k for n in needles):
            return True
        # Bare "key"/"auth" as a whole word (avoid masking e.g. "monkey"/"author").
        return k in ("key", "auth")


# ===========================================================================
# 2. FieldCipher — encrypt sensitive datastore fields at rest
# ===========================================================================
class FieldCipher:
    """
    A thin, friendly wrapper around :class:`cryptography.fernet.Fernet`.

    Use it to encrypt individual *fields* (a captured cookie, a token, a request
    body) before they are written to the SQLite datastore or the audit log, so
    that the database file on disk never contains plaintext secrets.

    Fernet gives us authenticated symmetric encryption (AES-128-CBC + HMAC) with
    a URL-safe base64 key. Tokens are URL-safe base64 strings, so they store
    cleanly in a TEXT column.

    Example::

        cipher = FieldCipher(FieldCipher.generate_key())
        token = cipher.encrypt("sk-supersecret")
        assert cipher.decrypt(token) == "sk-supersecret"
    """

    def __init__(self, key: bytes) -> None:
        """``key`` must be a 32-byte url-safe base64 key (see :meth:`generate_key`)."""
        if isinstance(key, str):
            key = key.encode("utf-8")
        # Fernet validates the key shape and raises a clear error if it's wrong.
        self._fernet = Fernet(key)

    # -- key construction helpers -----------------------------------------
    @staticmethod
    def generate_key() -> bytes:
        """Return a brand-new random Fernet key (32 url-safe base64 bytes)."""
        return Fernet.generate_key()

    @classmethod
    def from_key_b64(cls, key_b64: str) -> "FieldCipher":
        """Build a cipher from a base64 key string (e.g. read from a secret)."""
        if not key_b64:
            raise ValueError("from_key_b64: key string is empty")
        return cls(key_b64.encode("utf-8") if isinstance(key_b64, str) else key_b64)

    # -- encrypt / decrypt -------------------------------------------------
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt ``plaintext`` and return a token string.

        ``None`` is treated as the empty string, and ``encrypt("")`` works fine
        (it still returns a valid token), so callers don't need to special-case
        missing values.
        """
        if plaintext is None:
            plaintext = ""
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, token: str) -> str:
        """
        Decrypt a token produced by :meth:`encrypt` and return the plaintext.

        Deliberately forgiving: if ``token`` is empty or is **not** a valid
        Fernet token, the input is returned unchanged. That makes it safe to run
        this over a column that might still hold legacy *plaintext* data during a
        migration — plaintext passes straight through instead of crashing.
        """
        if token is None:
            return ""
        if not isinstance(token, str):
            token = str(token)
        if token == "":
            return ""
        try:
            return self._fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except (InvalidToken, binascii.Error, ValueError):
            # Not something we encrypted (already plaintext / corrupt) — return
            # it as-is so we never lose data or raise on benign input.
            return token


# ===========================================================================
# 3. SecretsStore — resolve secrets without putting them in code/logs
# ===========================================================================
class SecretsStore:
    """
    Look up secrets from the environment or a gitignored local file.

    Resolution order for ``get("data_key")``:

      1. Environment variable ``BBP_SECRET_DATA_KEY`` (name upper-cased).
      2. A key in the local secrets file (default ``config/secrets.local.yml``,
         which is git-ignored — see ``.gitignore``).

    The file is a simple ``KEY: value`` format (one per line). If PyYAML is
    installed we parse it as YAML; otherwise we fall back to a tiny line parser
    so the module still works with zero optional dependencies.

    Crucially, this class **never logs secret values**. :meth:`list_names` exists
    so tooling can show *which* secrets are configured without revealing them.
    """

    def __init__(self, secrets_path: str | Path = "config/secrets.local.yml") -> None:
        self.secrets_path = Path(secrets_path)
        # Cache the parsed file so we don't re-read it on every lookup.
        self._file_cache: dict[str, str] | None = None

    # -- env helpers -------------------------------------------------------
    @staticmethod
    def _env_var_name(name: str) -> str:
        """Map a secret name to its env-var name, e.g. 'data_key' -> 'BBP_SECRET_DATA_KEY'."""
        normalised = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
        return f"BBP_SECRET_{normalised}"

    # -- file helpers ------------------------------------------------------
    def _load_file(self) -> dict[str, str]:
        """Parse the local secrets file once, returning {name: value}."""
        if self._file_cache is not None:
            return self._file_cache

        data: dict[str, str] = {}
        if self.secrets_path.exists():
            text = self.secrets_path.read_text(encoding="utf-8")
            if _HAVE_YAML:
                try:
                    loaded = yaml.safe_load(text) or {}
                    if isinstance(loaded, dict):
                        data = {str(k): _stringify(v) for k, v in loaded.items()}
                    else:
                        data = self._parse_simple(text)
                except Exception:
                    # Malformed YAML shouldn't take the whole platform down;
                    # fall back to the line parser.
                    data = self._parse_simple(text)
            else:
                data = self._parse_simple(text)

        self._file_cache = data
        return data

    @staticmethod
    def _parse_simple(text: str) -> dict[str, str]:
        """
        Minimal ``KEY: value`` / ``KEY=value`` parser (no dependencies).

        Blank lines and ``#`` comments are ignored. Surrounding quotes on the
        value are stripped. This is intentionally tiny — the secrets file is not
        meant to hold complex structures.
        """
        out: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Accept either ':' or '=' as the separator.
            if ":" in line:
                key, _, value = line.partition(":")
            elif "=" in line:
                key, _, value = line.partition("=")
            else:
                continue
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                out[key] = value
        return out

    # -- public API --------------------------------------------------------
    def get(self, name: str, default: str | None = None) -> str | None:
        """
        Return the value of secret ``name``, or ``default`` if it is not set.

        Checks the environment first, then the local file. Never logs the value.
        """
        # 1. Environment variable wins (12-factor friendly, easy in CI).
        env_val = os.environ.get(self._env_var_name(name))
        if env_val is not None and env_val != "":
            return env_val

        # 2. Local secrets file. Try the exact name, then a few normalisations
        #    (case-insensitive, dashes/underscores interchangeable).
        file_data = self._load_file()
        if name in file_data:
            return file_data[name]
        wanted = re.sub(r"[^a-z0-9]+", "", name.lower())
        for key, value in file_data.items():
            if re.sub(r"[^a-z0-9]+", "", key.lower()) == wanted:
                return value

        return default

    def list_names(self) -> list[str]:
        """
        Return the names of all available secrets — **values are never returned**.

        Combines names found in the environment (the ``BBP_SECRET_*`` prefix is
        stripped) and names found in the local file. Useful for a ``status``
        command that wants to show what is configured without leaking anything.
        """
        names: set[str] = set()

        prefix = "BBP_SECRET_"
        for env_key in os.environ:
            if env_key.startswith(prefix) and len(env_key) > len(prefix):
                names.add(env_key[len(prefix):].lower())

        for file_key in self._load_file():
            names.add(str(file_key).lower())

        return sorted(names)


def _stringify(value) -> str:
    """Coerce a YAML-loaded scalar to a plain string (so callers always get str)."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# ===========================================================================
# 4. get_data_cipher — the at-rest encryption key for the datastore
# ===========================================================================
def get_data_cipher(
    secrets: SecretsStore | None = None,
    key_path: str = "data/.data_key",
) -> FieldCipher:
    """
    Return the :class:`FieldCipher` used to encrypt datastore/audit data at rest.

    The encryption key is resolved like this:

      1. If the secret ``DATA_KEY`` is configured (env ``BBP_SECRET_DATA_KEY`` or
         the local secrets file), use it. Best for production / CI, where the key
         is injected and never written to disk.
      2. Otherwise, read it from ``key_path``. If that file does not exist yet,
         generate a fresh key, write it (with ``0600`` permissions so only the
         owner can read it), and use that. This "just works" for local dev.

    The same key must be used for a given datastore for its whole life, or you
    won't be able to decrypt previously-stored fields — hence the persistent
    key file.
    """
    secrets = secrets or SecretsStore()

    # 1. Prefer an injected secret (never touches disk).
    key_from_secret = secrets.get("DATA_KEY")
    if key_from_secret:
        return FieldCipher.from_key_b64(key_from_secret)

    # 2. Fall back to a local key file, creating it on first use.
    path = Path(key_path)
    if path.exists():
        key = path.read_bytes().strip()
        if not key:
            # Empty/corrupt file — regenerate rather than crash.
            key = _write_new_key_file(path)
    else:
        key = _write_new_key_file(path)

    return FieldCipher(key)


def _write_new_key_file(path: Path) -> bytes:
    """Generate a new key, write it to ``path`` with 0600 perms, and return it."""
    key = FieldCipher.generate_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write first, then tighten permissions to owner read/write only.
    path.write_bytes(key)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        # Some filesystems (e.g. certain mounts on Windows) don't support chmod;
        # the key file is still gitignored, so degrade gracefully.
        pass
    return key


# ===========================================================================
# 5. RetentionPolicy — purge data that is too old to keep
# ===========================================================================
class RetentionPolicy:
    """
    Decide when captured data has aged out, and delete it from the datastore.

    Holding other people's secrets longer than necessary is a liability, so the
    platform keeps captured traffic and blind-callback records for a fixed number
    of ``days`` and then purges them.

    Example::

        policy = RetentionPolicy(days=30)
        policy.expired("2000-01-01T00:00:00+00:00")   # -> True (ancient)
        policy.purge(datastore)                         # -> {"captured_traffic": 12, ...}
    """

    def __init__(self, days: int) -> None:
        if days < 0:
            raise ValueError("RetentionPolicy days must be >= 0")
        self.days = int(days)

    # -- age checks --------------------------------------------------------
    def cutoff(self, now: datetime | None = None) -> datetime:
        """Return the UTC datetime before which records are considered expired."""
        now = now or datetime.now(tz=timezone.utc)
        return now - timedelta(days=self.days)

    def expired(self, iso_timestamp: str) -> bool:
        """
        Return ``True`` if ``iso_timestamp`` is older than ``days`` days ago (UTC).

        Accepts ISO-8601 strings, with or without timezone info and tolerating a
        trailing ``Z``. Unparseable input is treated as "not expired" (we never
        delete data we can't confidently date).
        """
        ts = _parse_iso(iso_timestamp)
        if ts is None:
            return False
        return ts < self.cutoff()

    # -- purging -----------------------------------------------------------
    def purge(self, datastore) -> dict:
        """
        Delete rows older than ``days`` from sensitive tables in ``datastore``.

        ``datastore`` is a thin SQLite wrapper exposing ``_execute(sql, params)``
        (preferred) and/or ``execute(sql, params)``. We DELETE aged rows from:

          * ``captured_traffic`` — using its ``created_at`` column.
          * ``callbacks``        — using its ``received_at`` column.

        Each table is guarded independently with try/except, so a missing table
        (or a schema that differs) never crashes the purge — it just contributes
        nothing to the result. Returns ``{table: rows_deleted}``.
        """
        cutoff_iso = self.cutoff().isoformat()
        runner = self._delete_runner(datastore)

        # (table name, timestamp column) pairs to sweep.
        targets = [
            ("captured_traffic", "created_at"),
            ("callbacks", "received_at"),
        ]

        results: dict[str, int] = {}
        for table, ts_column in targets:
            try:
                # Parameterise the cutoff value; table/column names are fixed
                # literals from our own list above (never user input).
                sql = f"DELETE FROM {table} WHERE {ts_column} < ?"
                deleted = runner(sql, (cutoff_iso,))
                results[table] = int(deleted)
            except Exception:
                # Missing table, missing column, or any DB hiccup: skip this one
                # and keep going. Defensive on purpose.
                continue

        return results

    @staticmethod
    def _delete_runner(datastore):
        """
        Return a callable ``run(sql, params) -> rows_deleted`` for ``datastore``.

        Prefers the low-level ``_execute`` (which returns a cursor whose
        ``rowcount`` tells us how many rows were deleted); falls back to a public
        ``execute`` if that's all the object offers.
        """
        impl = getattr(datastore, "_execute", None) or getattr(datastore, "execute", None)
        if impl is None:
            raise AttributeError("datastore has neither _execute nor execute")

        def run(sql: str, params) -> int:
            result = impl(sql, params)
            # _execute returns a sqlite3.Cursor; .rowcount is the delete count.
            rowcount = getattr(result, "rowcount", None)
            if rowcount is None or rowcount < 0:
                return 0
            return rowcount

        return run


# ---------------------------------------------------------------------------
# Small shared utilities
# ---------------------------------------------------------------------------
def _parse_iso(value: str) -> datetime | None:
    """
    Parse an ISO-8601 timestamp into a timezone-aware UTC datetime, or None.

    Handles a trailing 'Z' (which ``datetime.fromisoformat`` historically didn't
    like) and assumes UTC for naive timestamps, so comparisons are always
    apples-to-apples.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Manual smoke test: `python -m core.governance`
# (The real, assertable tests live in tests/test_governance_data.py.)
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover - illustrative only
    r = Redactor()
    demo = (
        "login password=hunter2 with Authorization: Bearer eyJabc.def.ghi "
        "and key AKIAABCDEFGHIJKLMNOP"
    )
    print("redact:      ", r.redact(demo))
    print("idempotent:  ", r.redact(r.redact(demo)) == r.redact(demo))

    c = FieldCipher(FieldCipher.generate_key())
    tok = c.encrypt("top-secret-value")
    print("encrypt:     ", tok[:24], "...")
    print("round-trip:  ", c.decrypt(tok) == "top-secret-value")
    print("plaintext ok:", c.decrypt("not-a-token") == "not-a-token")

    p = RetentionPolicy(days=30)
    print("old expired: ", p.expired("2000-01-01T00:00:00Z"))
    print("now expired: ", p.expired(datetime.now(tz=timezone.utc).isoformat()))
