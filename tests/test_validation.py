"""
Tests for the validation/benchmark scoring logic (offline).
"""

from validation.scoring import (
    ManifestEntry,
    aggregate,
    finding_confidence,
    match_target,
)


def _finding(**kw):
    base = {"id": 1, "type": "accesscontrol", "subtype": "horizontal", "url": "",
            "parameter": "", "context": "", "severity": "high", "status": "new",
            "evidence": "{}", "title": ""}
    base.update(kw)
    return base


def _entry(**kw):
    base = dict(id="e1", target="t", finding_type="accesscontrol", subtype="horizontal",
                endpoint="/api/users/", param="", severity="high", kind="findable",
                module="accesscontrol", note="")
    base.update(kw)
    return ManifestEntry(**base)


def test_finding_confidence_sources():
    assert finding_confidence(_finding(status="verified")) == 1.0
    assert finding_confidence(_finding(evidence='{"confidence": 0.55}')) == 0.55
    assert finding_confidence(_finding(evidence='{"tier": "confirmed"}')) == 0.95
    assert finding_confidence(_finding(evidence='{"tier": "needs-review"}')) == 0.5


def test_true_positive_above_threshold():
    f = _finding(url="http://h/api/users/1", evidence='{"confidence": 0.9}')
    res = match_target("t", [f], [_entry()], threshold=0.7)
    assert any(r.status == "tp" for r in res)


def test_surfaced_low_below_threshold():
    f = _finding(url="http://h/api/users/1", evidence='{"confidence": 0.5}')
    res = match_target("t", [f], [_entry()], threshold=0.7)
    assert any(r.status == "surfaced_low" for r in res)
    assert not any(r.status == "tp" for r in res)


def test_false_negative_when_missing():
    res = match_target("t", [], [_entry()], threshold=0.7)
    assert any(r.status == "fn" for r in res)


def test_false_positive_unmatched_high_conf():
    f = _finding(subtype="vertical", url="http://h/other", evidence='{"confidence": 0.95}')
    res = match_target("t", [f], [_entry()], threshold=0.7)
    assert any(r.status == "fp" for r in res)


def test_duplicate_not_false_positive():
    # two findings match the same single manifest entry -> one TP, one duplicate
    f1 = _finding(id=1, url="http://h/api/users/1", evidence='{"confidence": 0.9}')
    f2 = _finding(id=2, url="http://h/api/users/2", evidence='{"confidence": 0.9}')
    res = match_target("t", [f1, f2], [_entry()], threshold=0.7)
    statuses = sorted(r.status for r in res)
    assert "tp" in statuses and "duplicate" in statuses
    assert "fp" not in statuses


def test_human_puzzle_excluded_from_penalty():
    res = match_target("t", [], [_entry(id="hp", kind="human_puzzle")], threshold=0.7)
    assert any(r.status == "human_puzzle" for r in res)
    assert not any(r.status == "fn" for r in res)


def test_csp_noise_not_false_positive():
    f = _finding(type="xss", subtype="csp", severity="low", url="http://h/x",
                 evidence='{"tier": "needs-review"}')
    res = match_target("t", [f], [], threshold=0.7)
    assert any(r.status == "info" for r in res)
    assert not any(r.status == "fp" for r in res)


def test_aggregate_precision_recall():
    results = match_target("t", [_finding(url="http://h/api/users/1",
                                          evidence='{"confidence": 0.9}')], [_entry()], 0.7)
    agg = aggregate(results)
    assert agg["by_module"]["accesscontrol"]["precision"] == 1.0
    assert agg["by_module"]["accesscontrol"]["recall"] == 1.0
