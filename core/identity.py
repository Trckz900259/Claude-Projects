"""
identity.py — multi-identity / session manager (shared foundation).

Access-control testing is impossible (and unsafe) with one account. You need at
least two accounts YOU control — e.g. UserA (high-priv) and UserB (low-priv),
plus optionally "anonymous" — so that the only "victim" data ever touched is your
OWN. This module is the shared service that:

  * loads N identity profiles (cookies / bearer tokens / custom headers),
  * sends a request AS a chosen identity (each request carries exactly that
    identity's auth — no shared cookie jar, so identities never cross-contaminate),
  * refreshes an expired session mid-run via an optional re-login flow,
  * tracks each account's OWN object IDs, which is the backbone of the
    own-accounts-only safety rule (we never substitute an ID we can't attribute
    to one of your own accounts, unless you explicitly authorise a controlled
    sequential sweep).

Identities are defined in YAML — preferably a gitignored `*.identities.local.yml`
(so tokens are never committed), referenced from the program profile via
`identities_file:`, or inline under `identities:`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.config import ProgramConfig
from core.exceptions import BBPlatformError
from core.http_engine import HttpEngine, HttpResult


class IdentityError(BBPlatformError):
    """Raised for misconfigured identities or when too few are provided."""


@dataclass
class ReloginFlow:
    """How to obtain a fresh token when a session expires mid-run."""

    method: str = "POST"
    url: str = ""
    json: dict | None = None
    data: dict | None = None
    token_json_path: str = ""        # dotted path to the token in the JSON response
    set_header: str = "Authorization"
    header_prefix: str = "Bearer "
    set_cookie: str = ""             # if the token is a cookie instead of a header


@dataclass
class IdentityProfile:
    name: str
    role: str = ""                   # high_priv | low_priv | anonymous
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    owned_ids: list[str] = field(default_factory=list)   # IDs proven to be MINE
    relogin: ReloginFlow | None = None
    description: str = ""

    @property
    def is_anonymous(self) -> bool:
        # An identity with a re-login flow can authenticate even before it's
        # primed, so it is NOT anonymous. Only a declared 'anonymous' role, or an
        # identity with no auth AND no way to get any, counts as anonymous.
        if self.role == "anonymous":
            return True
        return not self.cookies and not self.headers and self.relogin is None

    def auth_type(self) -> str:
        if any(k.lower() == "authorization" for k in self.headers):
            return "bearer"
        if self.cookies:
            return "cookie"
        if self.headers:
            return "header"
        return "none"

    def auth_summary(self) -> str:
        """A REDACTED one-liner for the DB/dashboard (never the raw secret)."""
        for k, v in self.headers.items():
            if k.lower() == "authorization":
                return f"{v[:10]}…({len(v)})"
        if self.cookies:
            names = ", ".join(self.cookies.keys())
            return f"cookies: {names}"
        return "none (anonymous)"

    def request_headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        """Build the headers for ONE request as this identity (cookies inlined)."""
        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra:
            headers.update(extra)
        return headers


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _parse_profile(d: dict[str, Any]) -> IdentityProfile:
    auth = d.get("auth", {}) or {}
    relogin = None
    if d.get("relogin"):
        r = d["relogin"]
        relogin = ReloginFlow(
            method=str(r.get("method", "POST")).upper(),
            url=str(r.get("url", "")),
            json=r.get("json"),
            data=r.get("data"),
            token_json_path=str(r.get("token_json_path", "")),
            set_header=str(r.get("set_header", "Authorization")),
            header_prefix=str(r.get("header_prefix", "Bearer ")),
            set_cookie=str(r.get("set_cookie", "")),
        )
    return IdentityProfile(
        name=str(d["name"]),
        role=str(d.get("role", "")),
        cookies=dict(auth.get("cookies", {}) or {}),
        headers={str(k): str(v) for k, v in (auth.get("headers", {}) or {}).items()},
        owned_ids=[str(x) for x in (d.get("owned_ids", []) or [])],
        relogin=relogin,
        description=str(d.get("description", "")),
    )


def load_identities(config: ProgramConfig) -> list[IdentityProfile]:
    """Load identities from the program profile (inline and/or a referenced file)."""
    raw = config.raw or {}
    entries: list[dict] = []

    # Inline identities.
    if isinstance(raw.get("identities"), list):
        entries.extend(raw["identities"])

    # A referenced (preferably gitignored) identities file.
    ref = raw.get("identities_file")
    if ref:
        path = Path(ref)
        if not path.is_absolute():
            path = Path(config.source_path).parent / ref
        if not path.exists():
            raise IdentityError(f"identities_file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if isinstance(loaded.get("identities"), list):
            entries.extend(loaded["identities"])

    profiles = [_parse_profile(e) for e in entries if e.get("name")]
    return profiles


# ---------------------------------------------------------------------------
# Session manager
# ---------------------------------------------------------------------------
class SessionManager:
    """Holds the identities and sends requests AS a chosen identity."""

    def __init__(
        self,
        http: HttpEngine,
        profiles: list[IdentityProfile],
        logger: logging.Logger | None = None,
        expiry_statuses: tuple[int, ...] = (401,),
    ) -> None:
        self.http = http
        self.profiles = {p.name: p for p in profiles}
        self.log = logger or logging.getLogger("identity")
        self.expiry_statuses = expiry_statuses

    # -- lookups ----------------------------------------------------------
    def names(self) -> list[str]:
        return list(self.profiles)

    def get(self, name: str) -> IdentityProfile:
        if name not in self.profiles:
            raise IdentityError(f"Unknown identity {name!r}")
        return self.profiles[name]

    def authenticated(self) -> list[IdentityProfile]:
        return [p for p in self.profiles.values() if not p.is_anonymous]

    def require_min(self, n: int = 2) -> None:
        """OWN-ACCOUNTS-ONLY gate: refuse to run with fewer than n identities."""
        auth = self.authenticated()
        if len(auth) < n:
            raise IdentityError(
                f"Access-control testing requires at least {n} of YOUR OWN "
                f"authenticated accounts; only {len(auth)} configured. Add them to "
                f"your identities file (each is an account you control)."
            )

    # -- the OWN-ACCOUNTS-ONLY id check -----------------------------------
    def owned_ids(self) -> set[str]:
        out: set[str] = set()
        for p in self.profiles.values():
            out.update(str(x) for x in p.owned_ids)
        return out

    def is_own_id(self, value: str) -> bool:
        return str(value) in self.owned_ids()

    # -- the one call: send a request AS an identity ----------------------
    def request_as(
        self, identity: str, method: str, url: str, *,
        headers: dict[str, str] | None = None, **kw,
    ) -> HttpResult:
        profile = self.get(identity)
        send_headers = profile.request_headers(headers)
        result = self.http.request(method, url, headers=send_headers, **kw)

        # Refresh an expired session once, if a re-login flow is configured.
        if result.status_code in self.expiry_statuses and profile.relogin:
            self.log.info("Identity %r looks expired (%s); attempting re-login",
                          identity, result.status_code)
            if self._relogin(profile):
                send_headers = profile.request_headers(headers)
                result = self.http.request(method, url, headers=send_headers, **kw)
        return result

    def prime(self) -> None:
        """Proactively run each identity's re-login flow so tokens are fresh."""
        for p in self.profiles.values():
            if p.relogin and p.relogin.url:
                ok = self._relogin(p)
                self.log.info("primed identity %r: %s", p.name, "ok" if ok else "FAILED")

    def _relogin(self, profile: IdentityProfile) -> bool:
        flow = profile.relogin
        if not flow or not flow.url:
            return False
        try:
            res = self.http.request(flow.method, flow.url, json=flow.json, data=flow.data)
            if not res.ok:
                return False
            import json as _json

            body = _json.loads(res.text or "{}")
            token = _dig(body, flow.token_json_path) if flow.token_json_path else None
            if not token:
                self.log.warning("re-login for %r returned no token at %r",
                                 profile.name, flow.token_json_path)
                return False
            if flow.set_cookie:
                profile.cookies[flow.set_cookie] = str(token)
            else:
                profile.headers[flow.set_header] = f"{flow.header_prefix}{token}"
            self.log.info("re-login for %r succeeded; session refreshed", profile.name)
            return True
        except Exception as exc:
            self.log.warning("re-login for %r failed: %s", profile.name, exc)
            return False

    # -- persist metadata for the dashboard -------------------------------
    def persist(self, datastore, program_id: int) -> None:
        for p in self.profiles.values():
            datastore.upsert_identity(
                program_id, name=p.name, role=p.role,
                auth_type=p.auth_type(), auth_summary=p.auth_summary(),
                description=p.description,
            )


def _dig(obj: Any, dotted: str) -> Any:
    """Read a nested value by dotted path, e.g. 'authentication.token'."""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur
