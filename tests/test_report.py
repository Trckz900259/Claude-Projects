"""
Tests for the reporting layer: CVSS v3.1 maths, context-specific remediation,
and the two-audience explain engine.
"""

from report.cvss import base_score, rating_for, score_for_subtype
from report.explain import explain_finding
from report.remediation import remediation_for


# --- CVSS v3.1 formula -----------------------------------------------------
def test_cvss_known_critical_vector():
    # The canonical "worst case" vector scores 9.8 in the CVSS 3.1 spec.
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_reflected_xss_is_6_1_medium():
    cvss = score_for_subtype("reflected")
    assert cvss.score == 6.1
    assert cvss.rating == "medium"


def test_cvss_rating_bands():
    assert rating_for(0.0) == "none"
    assert rating_for(3.9) == "low"
    assert rating_for(6.1) == "medium"
    assert rating_for(7.0) == "high"
    assert rating_for(9.5) == "critical"


def test_cvss_csp_is_informational():
    cvss = score_for_subtype("csp")
    assert cvss.score == 0.0 and cvss.rating == "informational"


# --- remediation is context-specific --------------------------------------
def test_remediation_html_body_mentions_entity_encoding():
    rem = remediation_for("reflected", "html_body")
    assert "entity" in rem.output_encoding.lower()


def test_remediation_js_context_mentions_json():
    rem = remediation_for("reflected", "js_string")
    assert "json" in rem.output_encoding.lower()


def test_remediation_dom_mentions_trusted_types():
    rem = remediation_for("dom", "dom")
    joined = " ".join(rem.defence_in_depth).lower()
    assert "trusted types" in joined or "dompurify" in joined


def test_remediation_always_has_cwe_reference():
    rem = remediation_for("reflected", "html_body")
    assert any("CWE-79" in r for r in rem.references)


# --- explain engine: two audiences ----------------------------------------
def test_explain_learner_and_client_differ():
    finding = {
        "subtype": "reflected", "context": "html_body",
        "parameter": "q", "url": "http://h/s?q=1", "evidence": "{}",
    }
    learner = explain_finding(finding, audience="learner")
    client = explain_finding(finding, audience="client")
    assert "plain English" in learner
    assert "Root cause" in client
    assert learner != client
