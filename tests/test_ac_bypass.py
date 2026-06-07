"""
Tests for the 403-bypass permutation generators (offline — no network).
"""

from modules.accesscontrol.bypass import (
    header_variants,
    path_variants,
    version_downgrade_variants,
)


def test_path_variants_include_known_tricks():
    variants = dict(path_variants("https://x.com/admin/secret"))
    techs = set(variants)
    assert "case-variation" in techs
    assert "trailing-slash" in techs
    assert "nginx-dotdot-semicolon" in techs
    # the nginx trick inserts /..;/
    assert any("..;/" in url for url in variants.values())


def test_case_variation_changes_first_segment():
    variants = dict(path_variants("https://x.com/admin/secret"))
    assert "/Admin/secret" in variants["case-variation"]


def test_header_variants_include_ip_spoofing():
    variants = dict(header_variants("https://x.com/admin"))
    assert "X-Forwarded-For" in variants
    assert variants["X-Forwarded-For"]["X-Forwarded-For"] == "127.0.0.1"
    assert "X-Original-URL" in variants


def test_version_downgrade():
    out = dict(version_downgrade_variants("https://x.com/v2/users"))
    assert "api-version-downgrade" in out
    assert "/v1/users" in out["api-version-downgrade"]
