"""
Tests for the config / rules engine: it should load valid profiles and reject
invalid ones with clear errors (especially: missing User-Agent, empty scope).
"""

import textwrap

import pytest

from core.config import load_program_config
from core.exceptions import ConfigError


def _write(tmp_path, text: str):
    p = tmp_path / "prog.yml"
    p.write_text(textwrap.dedent(text), encoding="utf-8")
    return p


def test_loads_a_valid_profile(tmp_path):
    path = _write(
        tmp_path,
        """
        program: { name: acme, platform: hackerone, handle: acme }
        scope:
          in_scope:
            - { type: domain, value: acme.com }
        http:
          user_agent: "Tester (contact: t@acme.com)"
        rate_limit: { requests_per_second: 3, per_host_rps: 1, max_concurrency: 4 }
        rules: { automated_scanning_allowed: true }
        """,
    )
    cfg = load_program_config(path)
    assert cfg.name == "acme"
    assert cfg.rules.automated_scanning_allowed is True
    assert cfg.rate_limit.requests_per_second == 3
    assert cfg.scope.check("https://acme.com/").allowed
    assert not cfg.scope.check("https://other.com/").allowed


def test_missing_user_agent_is_rejected(tmp_path):
    path = _write(
        tmp_path,
        """
        program: { name: acme }
        scope: { in_scope: [ { type: domain, value: acme.com } ] }
        http: {}
        """,
    )
    with pytest.raises(ConfigError) as e:
        load_program_config(path)
    assert "user_agent" in str(e.value)


def test_empty_scope_is_rejected(tmp_path):
    path = _write(
        tmp_path,
        """
        program: { name: acme }
        scope: { in_scope: [] }
        http: { user_agent: "x (contact: t@acme.com)" }
        """,
    )
    with pytest.raises(ConfigError) as e:
        load_program_config(path)
    assert "in_scope" in str(e.value)


def test_automated_scanning_defaults_to_false(tmp_path):
    path = _write(
        tmp_path,
        """
        program: { name: acme }
        scope: { in_scope: [ { type: domain, value: acme.com } ] }
        http: { user_agent: "x (contact: t@acme.com)" }
        """,
    )
    cfg = load_program_config(path)
    # Safe default: scanning is OFF unless the program profile opts in.
    assert cfg.rules.automated_scanning_allowed is False


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        load_program_config(tmp_path / "does-not-exist.yml")


def test_bare_string_scope_entry_is_treated_as_domain(tmp_path):
    path = _write(
        tmp_path,
        """
        program: { name: acme }
        scope: { in_scope: [ "acme.com" ] }
        http: { user_agent: "x (contact: t@acme.com)" }
        """,
    )
    cfg = load_program_config(path)
    assert cfg.scope.check("https://sub.acme.com/").allowed
