"""
tokens.py — auth-token harvesting from captured traffic.

After you browse as your own accounts (via the mitmproxy capture), this finds
the auth material in that traffic — JWTs, bearer/API keys, Basic credentials,
session cookies — so it can pre-fill your identity profiles instead of you
copy-pasting tokens by hand. It also decodes JWT headers/claims (helpful for the
JWT tester later).

Everything here is offline string analysis of traffic you captured yourself.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

# A JWT is three base64url segments separated by dots; the first decodes to JSON
# starting '{"' — we use that to avoid matching random dotted strings.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{0,}")
# Header names that commonly carry API keys/tokens.
_KEY_HEADERS = {"x-api-key", "apikey", "api-key", "x-auth-token", "x-access-token", "token"}
# Cookie names that usually mean "session".
_SESSION_COOKIE_HINTS = ("session", "sess", "auth", "token", "jwt", "sid", "connect.sid")


@dataclass
class HarvestedToken:
    type: str           # 'jwt' | 'bearer' | 'basic' | 'api_key' | 'cookie'
    location: str       # where it was found, e.g. 'header:Authorization'
    value: str          # the raw value (kept locally only)
    meta: dict = field(default_factory=dict)

    def preview(self) -> str:
        v = self.value
        return f"{v[:12]}…({len(v)})" if len(v) > 16 else v


def b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> dict:
    """Decode a JWT's header + payload WITHOUT verifying (for analysis)."""
    out: dict = {}
    try:
        h, p, _sig = token.split(".")
        out["header"] = json.loads(b64url_decode(h))
        out["payload"] = json.loads(b64url_decode(p))
        out["alg"] = out["header"].get("alg")
    except Exception:
        pass
    return out


def harvest_from_headers(headers: dict[str, str]) -> list[HarvestedToken]:
    tokens: list[HarvestedToken] = []
    for name, value in (headers or {}).items():
        lname = name.lower()
        if not value:
            continue
        if lname == "authorization":
            if value.lower().startswith("bearer "):
                raw = value[7:].strip()
                if _JWT_RE.fullmatch(raw):
                    tokens.append(HarvestedToken("jwt", f"header:{name}", raw, decode_jwt(raw)))
                else:
                    tokens.append(HarvestedToken("bearer", f"header:{name}", raw))
            elif value.lower().startswith("basic "):
                creds = ""
                try:
                    creds = base64.b64decode(value[6:].strip()).decode("utf-8", "replace")
                except (binascii.Error, ValueError):
                    pass
                tokens.append(HarvestedToken("basic", f"header:{name}", value[6:].strip(),
                                             {"decoded": creds}))
        elif lname in _KEY_HEADERS:
            tokens.append(HarvestedToken("api_key", f"header:{name}", value))
        elif lname == "cookie":
            for part in value.split(";"):
                if "=" not in part:
                    continue
                cname, cval = part.strip().split("=", 1)
                if any(h in cname.lower() for h in _SESSION_COOKIE_HINTS):
                    kind = "jwt" if _JWT_RE.fullmatch(cval) else "cookie"
                    meta = decode_jwt(cval) if kind == "jwt" else {}
                    tokens.append(HarvestedToken(kind, f"cookie:{cname}", cval, meta))
    return tokens


def harvest_from_text(text: str) -> list[HarvestedToken]:
    """Find bare JWTs anywhere in a blob (e.g. a response body)."""
    found = []
    for m in set(_JWT_RE.findall(text or "")):
        found.append(HarvestedToken("jwt", "body", m, decode_jwt(m)))
    return found


def harvest_traffic(captured_rows) -> list[HarvestedToken]:
    """
    Harvest unique tokens across captured_traffic rows. Each row has req_headers
    and resp_headers stored as JSON strings.
    """
    seen: set[tuple[str, str]] = set()
    out: list[HarvestedToken] = []

    def _add(toks):
        for t in toks:
            sig = (t.type, t.value)
            if sig not in seen:
                seen.add(sig)
                out.append(t)

    for row in captured_rows:
        try:
            req_h = json.loads(row["req_headers"] or "{}")
            resp_h = json.loads(row["resp_headers"] or "{}")
        except Exception:
            req_h, resp_h = {}, {}
        _add(harvest_from_headers(req_h))
        # Set-Cookie in responses + JWTs in bodies.
        sc = resp_h.get("Set-Cookie") or resp_h.get("set-cookie")
        if sc:
            _add(harvest_from_headers({"cookie": sc.replace(",", ";")}))
        _add(harvest_from_text(row["resp_body"] or ""))
    return out


def suggest_identity_auth(tokens: list[HarvestedToken]) -> dict:
    """
    Turn harvested tokens into a ready-to-paste identity `auth:` block so you can
    drop it into your identities file.
    """
    auth: dict = {"headers": {}, "cookies": {}}
    for t in tokens:
        if t.type in ("jwt", "bearer"):
            auth["headers"]["Authorization"] = f"Bearer {t.value}"
        elif t.type == "api_key":
            header_name = t.location.split(":", 1)[-1]
            auth["headers"][header_name] = t.value
        elif t.type == "cookie":
            cname = t.location.split(":", 1)[-1]
            auth["cookies"][cname] = t.value
    if not auth["headers"]:
        auth.pop("headers")
    if not auth["cookies"]:
        auth.pop("cookies")
    return auth
