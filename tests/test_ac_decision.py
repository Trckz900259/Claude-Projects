"""
Tests for the comparison / decision engine — the false-positive-minimising brains.
"""

from modules.accesscontrol.decision import (
    compare_access,
    content_similarity,
    normalize_body,
    sensitive_values,
)

OWNER = '{"id": 1, "name": "Alice", "email": "alice@mine.test", "secret": "A-SSN-111"}'


def test_enforced_403_is_no_finding():
    cmp = compare_access(200, OWNER, 403, '{"error":"forbidden"}')
    assert not cmp.violation
    assert cmp.tier == "no-finding"


def test_attacker_gets_owner_private_data_is_high_confidence():
    # attacker received the SAME private object -> violation, high confidence
    cmp = compare_access(200, OWNER, 200, OWNER)
    assert cmp.violation
    assert cmp.confidence >= 0.8
    assert cmp.tier == "high-confidence"
    assert "A-SSN-111" not in cmp.reason  # reason is a summary, not the secret


def test_attacker_gets_different_data_is_not_a_finding():
    other = '{"id": 2, "name": "Bob", "email": "bob@mine.test", "secret": "B-SSN-222"}'
    cmp = compare_access(200, OWNER, 200, other)
    # different object -> low similarity, no marker hit -> not a clear violation
    assert cmp.confidence < 0.8


def test_marker_hit_drives_violation_even_if_wrapped():
    # owner's secret appears inside a larger attacker response -> strong signal
    wrapped = '{"data": {"id": 1, "secret": "A-SSN-111"}, "extra": "stuff"}'
    cmp = compare_access(200, OWNER, 200, wrapped)
    assert cmp.violation


def test_normalize_strips_volatile_fields():
    a = '{"id": 1, "csrf": "aaa", "timestamp": "2025-01-01T00:00:00Z"}'
    b = '{"id": 1, "csrf": "bbb", "timestamp": "2026-09-09T09:09:09Z"}'
    # after normalisation the volatile fields are blanked, so these match
    assert normalize_body(a) == normalize_body(b)
    assert content_similarity(a, b) == 1.0


def test_sensitive_values_extracted():
    vals = sensitive_values(OWNER)
    assert "alice@mine.test" in vals
    assert "A-SSN-111" in vals
