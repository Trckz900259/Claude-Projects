"""
Tests for auth-token harvesting and JWT decoding (offline string analysis).
"""

import base64
import json

from core.tokens import (
    b64url_decode,
    decode_jwt,
    harvest_from_headers,
    suggest_identity_auth,
)


def _make_jwt(payload: dict, alg: str = "HS256") -> str:
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': alg, 'typ': 'JWT'})}.{seg(payload)}.signaturepart"


def test_decode_jwt_reads_header_and_payload():
    tok = _make_jwt({"sub": "1", "role": "admin"})
    d = decode_jwt(tok)
    assert d["alg"] == "HS256"
    assert d["payload"]["role"] == "admin"


def test_harvest_detects_bearer_jwt():
    tok = _make_jwt({"sub": "1"})
    found = harvest_from_headers({"Authorization": f"Bearer {tok}"})
    assert any(t.type == "jwt" for t in found)


def test_harvest_detects_basic_auth():
    creds = base64.b64encode(b"alice:secret").decode()
    found = harvest_from_headers({"Authorization": f"Basic {creds}"})
    basic = [t for t in found if t.type == "basic"]
    assert basic and basic[0].meta["decoded"] == "alice:secret"


def test_harvest_detects_api_key_and_cookie():
    found = harvest_from_headers({
        "X-API-Key": "abcd1234",
        "Cookie": "sessionid=zzz; theme=dark",
    })
    types = {t.type for t in found}
    assert "api_key" in types
    assert "cookie" in types  # sessionid matched the session hint; theme ignored


def test_suggest_identity_auth_builds_block():
    tok = _make_jwt({"sub": "1"})
    found = harvest_from_headers({"Authorization": f"Bearer {tok}"})
    auth = suggest_identity_auth(found)
    assert auth["headers"]["Authorization"].startswith("Bearer ")


def test_b64url_decode_handles_padding():
    # 'abc' base64url-encodes to 'YWJj' (len 4, no padding needed)
    assert b64url_decode("YWJj") == b"abc"
