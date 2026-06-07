"""
Tests for the OOB engine (source discrimination) and the DNS rebinder scope gate.
"""

import pytest

from core.exceptions import OutOfScopeError
from core.oob import LocalHttpCollaborator, classify_source
from core.rebind import DnsRebinder, ip_to_hex, rbndr_hostname
from core.scope import ScopeEnforcer, ScopeRule


# --- source discrimination (the false-positive filter) --------------------
def test_target_ip_is_confirmed():
    cls, _ = classify_source("203.0.113.9", "anything", {"203.0.113.9"})
    assert cls == "target"


def test_known_scanner_is_flagged_false_positive():
    for ua in ("Slackbot-LinkExpanding 1.0", "facebookexternalhit/1.1",
               "Microsoft Office Word/16.0 SafeLinks"):
        cls, _ = classify_source("198.51.100.1", ua, set())
        assert cls == "third_party_scanner"


def test_unknown_source_needs_confirmation():
    cls, _ = classify_source("198.51.100.1", "curl/8.0", set())
    assert cls == "unknown"


# --- rebinding maths + scope gate -----------------------------------------
def test_ip_to_hex():
    assert ip_to_hex("127.0.0.1") == "7f000001"
    assert ip_to_hex("169.254.169.254") == "a9fea9fe"


def test_rbndr_hostname():
    assert rbndr_hostname("8.8.8.8", "169.254.169.254") == "08080808.a9fea9fe.rbndr.us"


def test_rebind_refuses_unauthorized_target():
    rb = DnsRebinder(scope=ScopeEnforcer(in_scope=[ScopeRule("domain", "example.com")]))
    with pytest.raises(OutOfScopeError):
        rb.make_rebind("8.8.8.8", "10.1.2.3")


def test_rebind_allows_explicitly_authorized_internal():
    rb = DnsRebinder(scope=None, allowed_internal=["169.254.169.254/32"])
    host = rb.make_rebind("8.8.8.8", "169.254.169.254")
    assert host.endswith(".rbndr.us")


# --- local collaborator payload format ------------------------------------
def test_local_collaborator_payload_url():
    c = LocalHttpCollaborator(advertise_host="10.0.0.5", port=9999)
    c.port = 9999
    url = c.payload_url("ssrfabc")
    assert url == "http://10.0.0.5:9999/ssrfabc"
