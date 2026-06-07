"""
Tests for the XSS pure-logic analyzers: context classification, CSP analysis,
DOM source->sink scanning, and payload selection. None of these touch the
network, so they're fast and deterministic.
"""

from modules.xss.context import classify_reflections
from modules.xss.csp import analyze_csp, parse_csp
from modules.xss.dom import DomAnalyzer
from modules.xss.payloads import new_marker, payloads_for
from modules.xss.reflection import inject_param


# --- context classification ------------------------------------------------
def test_marker_in_html_body_is_html_body_context():
    m = "bbpMARKER"
    ctxs = classify_reflections(f"<html><body><h1>Results for {m}</h1></body></html>", m)
    assert any(c.context == "html_body" for c in ctxs)


def test_marker_in_attribute_value_is_attribute_context():
    m = "bbpMARKER"
    html = f'<input type="text" value="{m}">'
    ctxs = classify_reflections(html, m)
    kinds = {c.context for c in ctxs}
    assert "attribute" in kinds
    attr = next(c for c in ctxs if c.context == "attribute")
    assert attr.quote == '"'


def test_marker_in_script_is_js_context():
    m = "bbpMARKER"
    html = f"<script>var x = '{m}';</script>"
    ctxs = classify_reflections(html, m)
    assert any(c.context == "js_string" for c in ctxs)


def test_marker_in_href_is_url_context():
    m = "bbpMARKER"
    html = f'<a href="{m}">link</a>'
    ctxs = classify_reflections(html, m)
    assert any(c.context == "url" for c in ctxs)


# --- payload selection -----------------------------------------------------
def test_payloads_are_context_appropriate_and_carry_marker():
    m = new_marker()
    body = payloads_for("html_body", m)
    assert all(m in p for p in body)
    assert any(p.startswith("<script>") for p in body)

    attr = payloads_for("attribute", m, quote='"')
    assert all(m in p for p in attr)
    assert any(p.startswith('">') for p in attr)  # breaks out of the quote+tag


# --- CSP analysis ----------------------------------------------------------
def test_csp_parse():
    p = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")
    assert p["script-src"] == ["'self'", "'unsafe-inline'"]


def test_csp_flags_unsafe_inline_high():
    issues = analyze_csp("script-src 'self' 'unsafe-inline'")
    assert any(i.severity == "high" and "unsafe-inline" in i.issue for i in issues)


def test_csp_missing_is_low_info():
    issues = analyze_csp(None)
    assert len(issues) == 1 and issues[0].severity == "low"


def test_csp_strong_policy_has_no_high_issues():
    issues = analyze_csp("default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'")
    assert all(i.severity != "high" for i in issues)


# --- DOM scanning ----------------------------------------------------------
def test_dom_scanner_finds_hash_to_innerhtml_flow():
    analyzer = DomAnalyzer(http=None)  # _scan doesn't use http
    code = "var data = location.hash.slice(1); el.innerHTML = data;"
    flows = analyzer._scan(code, "inline #0")
    assert flows, "expected a source->sink flow"
    assert "location.hash" in flows[0].source
    assert "innerHTML" in flows[0].sink


def test_dom_scanner_ignores_safe_code():
    analyzer = DomAnalyzer(http=None)
    code = "var x = 1 + 2; console.log(x);"
    assert analyzer._scan(code, "inline #0") == []


# --- param injection -------------------------------------------------------
def test_inject_param_sets_value():
    out = inject_param("http://h/x?q=old&a=1", "q", "NEW")
    assert "q=NEW" in out
    assert "a=1" in out


# --- dalfox output parsing (real schema: payload, data=poc-url, type, ...) --
def test_dalfox_parser_handles_real_schema():
    from modules.xss.dalfox import _parse

    raw = (
        '[\n'
        '{"type":"V","payload":"\\"><img src=x onerror=alert(1)>",'
        '"data":"http://h/s?q=%22%3E%3Cimg%3E","severity":"High","cwe":"CWE-79",'
        '"evidence":"line 1"},\n'
        '{}]'
    )
    res = _parse(raw)
    assert len(res) == 1  # the trailing empty {} is skipped
    assert res[0].type == "V"
    assert res[0].severity == "High"
    assert res[0].poc_url.startswith("http")
    assert "img src=x" in res[0].payload
