"""
Tests for the JWT forgery primitives (offline — no network).
"""

import jwt as pyjwt

from modules.accesscontrol.jwt_tester import (
    _b64url_decode,
    _b64url_encode,
    _encode_unsigned,
    _sign_hs256,
    decode_parts,
)


def test_b64url_roundtrip():
    assert _b64url_decode(_b64url_encode(b"hello world")) == b"hello world"


def test_sign_hs256_is_verifiable_by_pyjwt():
    token = _sign_hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "99", "role": "admin"}, "secret")
    decoded = pyjwt.decode(token, "secret", algorithms=["HS256"])
    assert decoded["sub"] == "99"
    assert decoded["role"] == "admin"


def test_sign_hs256_fails_with_wrong_secret():
    token = _sign_hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
    try:
        pyjwt.decode(token, "wrong", algorithms=["HS256"])
        assert False, "should have raised"
    except pyjwt.InvalidSignatureError:
        pass


def test_alg_none_token_has_empty_signature():
    token = _encode_unsigned({"alg": "none", "typ": "JWT"}, {"sub": "99"}) + "."
    assert token.endswith(".")
    header, payload, sig = decode_parts(token)
    assert header["alg"] == "none"
    assert payload["sub"] == "99"
    assert sig == ""


def test_decode_parts_roundtrip():
    h, p = {"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"}
    token = _sign_hs256(h, p, "k")
    dh, dp, _ = decode_parts(token)
    assert dh["alg"] == "HS256" and dp["role"] == "user"
