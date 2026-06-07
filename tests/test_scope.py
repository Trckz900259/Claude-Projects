"""
Tests for the scope allow-list — the platform's most important safety control.

These tests are the proof that out-of-scope targets are refused. If any of them
fail, the platform must not be used.
"""

import pytest

from core.scope import ScopeEnforcer, ScopeRule, host_of


# --- host parsing ----------------------------------------------------------
@pytest.mark.parametrize(
    "target,expected",
    [
        ("https://API.Example.com:8443/path?x=1", "api.example.com"),
        ("http://example.com", "example.com"),
        ("example.com", "example.com"),
        ("example.com/some/path", "example.com"),
        ("https://user:pass@host.example.com/", "host.example.com"),
        ("", ""),
    ],
)
def test_host_of(target, expected):
    assert host_of(target) == expected


# --- the core allow / deny behaviour --------------------------------------
@pytest.fixture
def enforcer():
    return ScopeEnforcer(
        in_scope=[
            ScopeRule("domain", "example.com"),
            ScopeRule("wildcard", "*.api.example.com"),
            ScopeRule("url", "https://app.example.com/dashboard"),
            ScopeRule("cidr", "192.0.2.0/24"),
        ],
        out_of_scope=[
            ScopeRule("domain", "blog.example.com"),
            ScopeRule("url", "https://example.com/admin"),
        ],
    )


def test_apex_in_scope(enforcer):
    assert enforcer.check("https://example.com/").allowed


def test_subdomain_in_scope_via_domain_rule(enforcer):
    # 'domain' covers apex AND subdomains.
    assert enforcer.check("https://shop.example.com/products?q=1").allowed


def test_completely_unrelated_host_is_refused(enforcer):
    decision = enforcer.check("https://evil.com/")
    assert not decision.allowed
    assert "default-deny" in decision.reason


def test_out_of_scope_domain_is_refused(enforcer):
    decision = enforcer.check("https://blog.example.com/post/1")
    assert not decision.allowed
    assert "OUT-OF-SCOPE" in decision.reason


def test_deny_list_beats_allow_list(enforcer):
    # /admin is denied even though example.com is in scope -> deny wins.
    decision = enforcer.check("https://example.com/admin/settings")
    assert not decision.allowed
    assert "OUT-OF-SCOPE" in decision.reason


def test_wildcard_matches_subdomain_only(enforcer):
    assert enforcer.check("https://v2.api.example.com/").allowed
    # The wildcard *.api.example.com must NOT match the bare apex api.example.com
    # ... but note 'api.example.com' is still in scope here via the broader
    # 'domain: example.com' rule, so we test the wildcard in isolation instead:
    only_wild = ScopeEnforcer(in_scope=[ScopeRule("wildcard", "*.api.example.com")])
    assert only_wild.check("https://v2.api.example.com/").allowed
    assert not only_wild.check("https://api.example.com/").allowed


def test_url_rule_requires_prefix_match():
    # Isolate the url rule: a host covered ONLY by a url-prefix rule (and not by
    # any broader domain rule) is allowed on the matching path and refused
    # elsewhere.
    only_url = ScopeEnforcer(
        in_scope=[ScopeRule("url", "https://app.standalone.test/dashboard")]
    )
    assert only_url.check("https://app.standalone.test/dashboard/widgets").allowed
    assert not only_url.check("https://app.standalone.test/other").allowed
    # Wrong scheme is also refused.
    assert not only_url.check("http://app.standalone.test/dashboard").allowed


def test_cidr_matches_ip_literals_only(enforcer):
    assert enforcer.check("http://192.0.2.10/").allowed
    assert not enforcer.check("http://198.51.100.5/").allowed


def test_empty_or_garbage_target_is_refused(enforcer):
    assert not enforcer.check("").allowed
    assert not enforcer.check("not a url").allowed


def test_default_deny_with_no_rules():
    # An enforcer with an empty allow-list refuses everything.
    empty = ScopeEnforcer(in_scope=[])
    assert not empty.check("https://example.com/").allowed
