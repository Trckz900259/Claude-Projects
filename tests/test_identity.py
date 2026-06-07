"""
Tests for the multi-identity / session manager — especially the safety logic:
identity isolation inputs, the own-accounts-only gate, and owned-id tracking.
"""

import pytest

from core.identity import (
    IdentityProfile,
    ReloginFlow,
    SessionManager,
    _parse_profile,
)


def test_parse_profile_reads_auth_and_owned_ids():
    p = _parse_profile({
        "name": "userA", "role": "high_priv",
        "auth": {"headers": {"Authorization": "Bearer xyz"}, "cookies": {"sid": "1"}},
        "owned_ids": [1, "a-uuid"],
    })
    assert p.name == "userA"
    assert p.headers["Authorization"] == "Bearer xyz"
    assert p.cookies["sid"] == "1"
    assert p.owned_ids == ["1", "a-uuid"]  # coerced to strings


def test_is_anonymous_logic():
    anon = IdentityProfile(name="anon", role="anonymous")
    assert anon.is_anonymous
    # empty auth but has a re-login flow -> can authenticate -> NOT anonymous
    relogin = IdentityProfile(name="u", role="low_priv",
                              relogin=ReloginFlow(url="http://x/login"))
    assert not relogin.is_anonymous
    # empty auth, no relogin -> anonymous
    empty = IdentityProfile(name="e", role="low_priv")
    assert empty.is_anonymous
    # has a header -> not anonymous
    hdr = IdentityProfile(name="h", headers={"Authorization": "Bearer x"})
    assert not hdr.is_anonymous


def test_request_headers_inlines_cookies():
    p = IdentityProfile(name="u", cookies={"a": "1", "b": "2"},
                        headers={"X-Test": "y"})
    h = p.request_headers({"Extra": "z"})
    assert h["X-Test"] == "y"
    assert h["Extra"] == "z"
    assert "a=1" in h["Cookie"] and "b=2" in h["Cookie"]


def test_require_min_enforces_own_accounts_only():
    # one authenticated identity + an anonymous one -> still < 2 authenticated
    profiles = [
        IdentityProfile(name="userA", role="high_priv", headers={"Authorization": "Bearer a"}),
        IdentityProfile(name="anon", role="anonymous"),
    ]
    sm = SessionManager(http=None, profiles=profiles)
    with pytest.raises(Exception):
        sm.require_min(2)

    profiles.append(
        IdentityProfile(name="userB", role="low_priv", headers={"Authorization": "Bearer b"})
    )
    sm2 = SessionManager(http=None, profiles=profiles)
    sm2.require_min(2)  # now 2 authenticated -> ok


def test_owned_ids_and_is_own_id():
    profiles = [
        IdentityProfile(name="userA", owned_ids=["1", "100"], headers={"Authorization": "x"}),
        IdentityProfile(name="userB", owned_ids=["2"], headers={"Authorization": "y"}),
    ]
    sm = SessionManager(http=None, profiles=profiles)
    assert sm.owned_ids() == {"1", "2", "100"}
    assert sm.is_own_id("1") and sm.is_own_id(2)
    assert not sm.is_own_id("9999")  # a foreign id is NOT one of mine
