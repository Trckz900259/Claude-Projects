"""
config.py — the config / rules engine.

A *program profile* is a single YAML file under /config describing ONE bug
bounty program: what's in scope, the rate limits, the User-Agent to identify
ourselves with, whether automated scanning is allowed, and the OOB callback
domain. Nothing in this platform targets anything that isn't spelled out here —
there are no hardcoded targets anywhere in the code.

This module reads that YAML, validates it (with friendly errors), and hands back
strongly-typed objects the rest of the platform uses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.exceptions import ConfigError
from core.scope import ScopeEnforcer, ScopeRule


# ---------------------------------------------------------------------------
# Typed config sections
# ---------------------------------------------------------------------------
@dataclass
class RateLimitConfig:
    requests_per_second: float = 2.0
    per_host_rps: float = 1.0
    max_concurrency: int = 5


@dataclass
class HttpConfig:
    # REQUIRED: an identifiable researcher User-Agent on every request.
    user_agent: str = ""
    timeout_seconds: float = 15.0
    follow_redirects: bool = True
    verify_tls: bool = True
    max_retries: int = 2


@dataclass
class RulesConfig:
    # SAFE DEFAULT: automated scanning is OFF unless a program explicitly allows
    # it. Modules must refuse to run automated scans when this is False.
    automated_scanning_allowed: bool = False
    # If True, only passive/manual ("eyeball") work is expected — extra caution.
    eyeball_only: bool = False
    notes: str = ""


@dataclass
class CallbackConfig:
    # interactsh domain used for blind/OOB XSS callbacks (filled in per program).
    interactsh_domain: str = ""
    interactsh_server: str = "https://oast.fun"


@dataclass
class NotificationsConfig:
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    @property
    def any_configured(self) -> bool:
        return bool(self.discord_webhook or (self.telegram_bot_token and self.telegram_chat_id))


@dataclass
class ProgramConfig:
    """The fully-parsed, validated profile for one program."""

    name: str
    platform: str
    handle: str
    scope: ScopeEnforcer
    rules: RulesConfig
    rate_limit: RateLimitConfig
    http: HttpConfig
    callback: CallbackConfig
    notifications: NotificationsConfig
    source_path: str
    raw: dict[str, Any] = field(default_factory=dict)

    # Convenience: a flat, human-readable list of in-scope entries (for reports).
    @property
    def in_scope_summary(self) -> list[str]:
        return [f"{r.type}:{r.value}" for r in self.scope.in_scope]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def _parse_scope_rules(entries: Any, where: str) -> list[ScopeRule]:
    """Turn a list of {type, value} dicts (or bare strings) into ScopeRules."""
    rules: list[ScopeRule] = []
    if entries is None:
        return rules
    if not isinstance(entries, list):
        raise ConfigError(f"'{where}' must be a list, got {type(entries).__name__}")

    for i, entry in enumerate(entries):
        if isinstance(entry, str):
            # Shorthand: a bare string is treated as a domain entry.
            rules.append(ScopeRule(type="domain", value=entry.strip()))
            continue
        if not isinstance(entry, dict) or "value" not in entry:
            raise ConfigError(
                f"'{where}[{i}]' must be a string or a mapping with a 'value' key"
            )
        rule_type = str(entry.get("type", "domain")).strip().lower()
        try:
            rules.append(ScopeRule(type=rule_type, value=str(entry["value"]).strip()))
        except ValueError as exc:
            raise ConfigError(f"'{where}[{i}]': {exc}") from exc
    return rules


def load_program_config(path: str | Path) -> ProgramConfig:
    """
    Load and validate a program profile from a YAML file.

    Raises ConfigError (with a clear message) if anything is wrong, so a beginner
    sees exactly what to fix rather than a confusing stack trace.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse YAML in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")

    # --- program identity ---
    program = data.get("program", {})
    if not isinstance(program, dict) or not program.get("name"):
        raise ConfigError("Config must have program.name set")

    # --- scope (the allow-list) ---
    scope_block = data.get("scope", {})
    if not isinstance(scope_block, dict):
        raise ConfigError("'scope' must be a mapping with 'in_scope' (and optional 'out_of_scope')")
    in_scope = _parse_scope_rules(scope_block.get("in_scope"), "scope.in_scope")
    out_of_scope = _parse_scope_rules(scope_block.get("out_of_scope"), "scope.out_of_scope")
    if not in_scope:
        raise ConfigError(
            "scope.in_scope is empty — there is nothing to test. "
            "Add at least one in-scope entry (the platform is default-deny)."
        )
    scope = ScopeEnforcer(in_scope=in_scope, out_of_scope=out_of_scope)

    # --- http (User-Agent is REQUIRED by the safety rules) ---
    http_block = data.get("http", {}) or {}
    user_agent = str(http_block.get("user_agent", "")).strip()
    if not user_agent:
        raise ConfigError(
            "http.user_agent is required. Set an identifiable researcher "
            "User-Agent, e.g. 'Jane Researcher BugBounty "
            "(contact: jane@example.com)'."
        )
    http = HttpConfig(
        user_agent=user_agent,
        timeout_seconds=float(http_block.get("timeout_seconds", 15.0)),
        follow_redirects=bool(http_block.get("follow_redirects", True)),
        verify_tls=bool(http_block.get("verify_tls", True)),
        max_retries=int(http_block.get("max_retries", 2)),
    )

    # --- rate limits ---
    rl = data.get("rate_limit", {}) or {}
    rate_limit = RateLimitConfig(
        requests_per_second=float(rl.get("requests_per_second", 2.0)),
        per_host_rps=float(rl.get("per_host_rps", 1.0)),
        max_concurrency=int(rl.get("max_concurrency", 5)),
    )

    # --- rules ---
    rules_block = data.get("rules", {}) or {}
    rules = RulesConfig(
        automated_scanning_allowed=bool(rules_block.get("automated_scanning_allowed", False)),
        eyeball_only=bool(rules_block.get("eyeball_only", False)),
        notes=str(rules_block.get("notes", "")),
    )

    # --- callback (interactsh) ---
    cb = data.get("callback", {}) or {}
    callback = CallbackConfig(
        interactsh_domain=str(cb.get("interactsh_domain", "")).strip(),
        interactsh_server=str(cb.get("interactsh_server", "https://oast.fun")).strip(),
    )

    # --- notifications ---
    nb = data.get("notifications", {}) or {}
    notifications = NotificationsConfig(
        discord_webhook=str(nb.get("discord_webhook", "")).strip(),
        telegram_bot_token=str(nb.get("telegram_bot_token", "")).strip(),
        telegram_chat_id=str(nb.get("telegram_chat_id", "")).strip(),
    )

    return ProgramConfig(
        name=str(program["name"]),
        platform=str(program.get("platform", "unknown")),
        handle=str(program.get("handle", program["name"])),
        scope=scope,
        rules=rules,
        rate_limit=rate_limit,
        http=http,
        callback=callback,
        notifications=notifications,
        source_path=str(path),
        raw=data,
    )
