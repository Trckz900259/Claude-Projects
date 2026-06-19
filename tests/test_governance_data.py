"""
Tests for the data-governance layer (core/governance.py).

These prove the safety-critical behaviour:

  * Redactor masks JWTs, AWS keys, bearer tokens and password=... pairs, and is
    idempotent; redact_dict masks values under sensitive key names.
  * FieldCipher round-trips (encrypt -> decrypt == original) and leaves plaintext
    untouched when asked to decrypt something that isn't a token.
  * RetentionPolicy.expired is True for an ancient timestamp and False for now,
    and purge() deletes aged rows from a sqlite-like store while ignoring
    missing tables.
"""

from datetime import datetime, timedelta, timezone

from core.governance import (
    FieldCipher,
    Redactor,
    RetentionPolicy,
)


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------
def test_redact_masks_a_jwt():
    r = Redactor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36"
    out = r.redact(f"token is {jwt} here")
    assert jwt not in out
    assert "[REDACTED:jwt]" in out


def test_redact_masks_an_aws_key():
    r = Redactor()
    key = "AKIAIOSFODNN7EXAMPLE"  # 'AKIA' + 16 upper alphanumerics
    out = r.redact(f"aws id {key} end")
    assert key not in out
    assert "[REDACTED:aws_key]" in out


def test_redact_masks_a_bearer_token():
    r = Redactor()
    out = r.redact("Authorization: Bearer abc123DEF456ghi789JKL000mno")
    # The scheme is preserved, the credential is gone.
    assert "Bearer" in out
    assert "[REDACTED:bearer]" in out
    assert "abc123DEF456ghi789JKL000mno" not in out


def test_redact_masks_password_kv():
    r = Redactor()
    out = r.redact("user=alice password=Sup3rSecret! next=ok")
    assert "Sup3rSecret!" not in out
    assert "[REDACTED:password]" in out
    # Non-secret fields are left intact.
    assert "user=alice" in out


def test_redact_is_idempotent():
    r = Redactor()
    sample = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaa "
        "password=hunter2 AKIAIOSFODNN7EXAMPLE"
    )
    once = r.redact(sample)
    twice = r.redact(once)
    assert once == twice


def test_redact_does_not_corrupt_normal_text():
    r = Redactor()
    text = "The quick brown fox jumps over the lazy dog. Visit https://example.com/page?id=7"
    assert r.redact(text) == text


def test_redact_dict_masks_sensitive_key():
    r = Redactor()
    data = {
        "username": "alice",
        "password": "hunter2",
        "nested": {"api_key": "AKIAEXAMPLEKEY12345X", "note": "fine"},
        "items": ["plain", "Bearer eyJa.bb.cc"],
    }
    out = r.redact_dict(data)

    # Whole values masked for sensitive keys.
    assert out["password"] == "[REDACTED]"
    assert out["nested"]["api_key"] == "[REDACTED]"
    # Non-sensitive values preserved / string-redacted.
    assert out["username"] == "alice"
    assert out["nested"]["note"] == "fine"
    # Secrets inside list strings are still scrubbed.
    assert "[REDACTED:bearer]" in out["items"][1]
    # Original input is not mutated.
    assert data["password"] == "hunter2"


# ---------------------------------------------------------------------------
# FieldCipher
# ---------------------------------------------------------------------------
def test_fieldcipher_round_trip():
    cipher = FieldCipher(FieldCipher.generate_key())
    secret = "sk-live-1234567890-very-secret"
    token = cipher.encrypt(secret)
    assert token != secret  # actually encrypted
    assert cipher.decrypt(token) == secret


def test_fieldcipher_empty_plaintext():
    cipher = FieldCipher(FieldCipher.generate_key())
    token = cipher.encrypt("")
    assert cipher.decrypt(token) == ""


def test_fieldcipher_decrypt_of_plaintext_returns_unchanged():
    cipher = FieldCipher(FieldCipher.generate_key())
    # Not a Fernet token -> returned as-is (safe over already-plaintext data).
    assert cipher.decrypt("just-plain-text") == "just-plain-text"


def test_fieldcipher_from_key_b64_round_trip():
    key = FieldCipher.generate_key()  # bytes of a url-safe base64 key
    cipher = FieldCipher.from_key_b64(key.decode("utf-8"))
    token = cipher.encrypt("hello")
    assert cipher.decrypt(token) == "hello"


# ---------------------------------------------------------------------------
# RetentionPolicy
# ---------------------------------------------------------------------------
def test_retention_expired_true_for_old_and_false_for_now():
    policy = RetentionPolicy(days=30)
    assert policy.expired("2000-01-01T00:00:00+00:00") is True
    assert policy.expired(datetime.now(tz=timezone.utc).isoformat()) is False


def test_retention_expired_handles_trailing_z():
    policy = RetentionPolicy(days=1)
    old = (datetime.now(tz=timezone.utc) - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    assert policy.expired(old) is True


class _FakeStore:
    """Minimal in-memory stand-in exposing the datastore's _execute signature."""

    def __init__(self):
        now = datetime.now(tz=timezone.utc)
        old = (now - timedelta(days=100)).isoformat()
        fresh = now.isoformat()
        # rows: (id, timestamp)
        self.captured_traffic = [(1, old), (2, old), (3, fresh)]
        self.callbacks = [(1, old), (2, fresh)]

    def _execute(self, sql, params):
        cutoff = params[0]
        table = "captured_traffic" if "captured_traffic" in sql else "callbacks"
        rows = getattr(self, table)
        kept = [r for r in rows if r[1] >= cutoff]
        deleted = len(rows) - len(kept)
        setattr(self, table, kept)
        return _FakeCursor(deleted)


class _FakeCursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount


def test_retention_purge_deletes_aged_rows():
    policy = RetentionPolicy(days=30)
    store = _FakeStore()
    result = policy.purge(store)
    assert result["captured_traffic"] == 2
    assert result["callbacks"] == 1
    # Only the fresh rows remain.
    assert len(store.captured_traffic) == 1
    assert len(store.callbacks) == 1


def test_retention_purge_is_defensive_about_missing_tables():
    policy = RetentionPolicy(days=30)

    class _Broken:
        def _execute(self, sql, params):
            raise RuntimeError("no such table")

    # Should not raise; just returns no deletions.
    result = policy.purge(_Broken())
    assert result == {}
