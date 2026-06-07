"""
scope.py — the safety heart of the platform: the SCOPE ALLOW-LIST.

The single most important rule of this project:

    A target is touched ONLY IF it matches an explicit in-scope entry in the
    active program config. Anything else is refused at the HTTP layer.

This module turns that rule into code. It is deliberately:

  * default-deny      — if nothing on the allow-list matches, the answer is NO.
  * deny-precedent    — an out-of-scope entry always wins over an in-scope one.
  * dependency-free   — pure standard-library logic, easy to read and to test.

Scope entry types supported (set in the program YAML):

  domain   : "example.com"      -> matches example.com AND any subdomain
  wildcard : "*.example.com"    -> matches subdomains only (not the apex)
  url      : "https://x.com/app/" -> matches that exact URL prefix (host + path)
  cidr     : "192.0.2.0/24"     -> matches IP-literal hosts inside that range
  regex    : "^api[0-9]+\\.x\\.com$" -> advanced: full-match regex on the host

Everything else (anything not matched by an in-scope rule) is refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Small value objects
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScopeRule:
    """One line of the allow-list (or deny-list)."""

    type: str  # "domain" | "wildcard" | "url" | "cidr" | "regex"
    value: str

    def __post_init__(self) -> None:
        valid = {"domain", "wildcard", "url", "cidr", "regex"}
        if self.type not in valid:
            raise ValueError(
                f"Unknown scope rule type {self.type!r}. "
                f"Valid types: {', '.join(sorted(valid))}"
            )


@dataclass(frozen=True)
class ScopeDecision:
    """The result of a scope check — always carries a human-readable reason."""

    allowed: bool
    reason: str
    matched_rule: Optional[ScopeRule] = None

    def __bool__(self) -> bool:  # lets callers do `if decision: ...`
        return self.allowed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def host_of(target: str) -> str:
    """
    Pull the bare hostname out of a URL or host string, lower-cased and without
    any port. Returns "" if we cannot find one.

    Examples:
        "https://API.Example.com:8443/x" -> "api.example.com"
        "example.com"                    -> "example.com"
    """
    target = (target or "").strip()
    if not target:
        return ""

    # If there is a scheme (http://, https://) urlparse gives us .hostname
    # cleanly. If not, prepend a scheme so urlparse treats it as a host.
    parsed = urlparse(target if "//" in target else f"//{target}", scheme="http")
    host = parsed.hostname or ""
    return host.lower()


def _looks_like_ip(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# The enforcer
# ---------------------------------------------------------------------------
class ScopeEnforcer:
    """
    Holds a program's in-scope and out-of-scope rules and answers one question:
    "Am I allowed to touch this target?"

    Usage:
        enforcer = ScopeEnforcer(in_scope=[...], out_of_scope=[...])
        decision = enforcer.check("https://api.example.com/users?id=1")
        if not decision.allowed:
            raise OutOfScopeError(target, decision.reason)
    """

    def __init__(
        self,
        in_scope: list[ScopeRule],
        out_of_scope: Optional[list[ScopeRule]] = None,
    ) -> None:
        self.in_scope: list[ScopeRule] = list(in_scope or [])
        self.out_of_scope: list[ScopeRule] = list(out_of_scope or [])
        # Pre-compile any regex rules once, so checks stay fast.
        self._compiled: dict[str, re.Pattern[str]] = {}
        for rule in self.in_scope + self.out_of_scope:
            if rule.type == "regex":
                self._compiled[rule.value] = re.compile(rule.value, re.IGNORECASE)

    # -- public API --------------------------------------------------------
    def check(self, target: str) -> ScopeDecision:
        """
        Decide whether `target` (a URL or a host) may be touched.

        Order of evaluation (this order is the safety guarantee):
          1. If ANY out-of-scope rule matches -> DENY (deny wins, always).
          2. If ANY in-scope rule matches     -> ALLOW.
          3. Otherwise                         -> DENY (default-deny).
        """
        host = host_of(target)
        if not host:
            return ScopeDecision(False, f"Could not parse a hostname from {target!r}")

        # 1) Deny-list takes precedence — check it FIRST.
        for rule in self.out_of_scope:
            if self._matches(rule, host, target):
                return ScopeDecision(
                    False,
                    f"Matched OUT-OF-SCOPE rule ({rule.type} = {rule.value})",
                    rule,
                )

        # 2) Must match the allow-list to be permitted.
        for rule in self.in_scope:
            if self._matches(rule, host, target):
                return ScopeDecision(
                    True,
                    f"Matched in-scope rule ({rule.type} = {rule.value})",
                    rule,
                )

        # 3) Nothing matched -> refuse.
        return ScopeDecision(
            False,
            f"Host {host!r} is not on the in-scope allow-list (default-deny)",
        )

    def is_allowed(self, target: str) -> bool:
        """Convenience boolean form of check()."""
        return self.check(target).allowed

    # -- matching logic ----------------------------------------------------
    def _matches(self, rule: ScopeRule, host: str, original_target: str) -> bool:
        """Return True if `rule` covers this host/target."""
        value = rule.value.strip().lower()

        if rule.type == "domain":
            # apex match OR any subdomain of it
            return host == value or host.endswith("." + value)

        if rule.type == "wildcard":
            # "*.example.com" -> subdomains only
            suffix = value[1:] if value.startswith("*") else value  # ".example.com"
            if not suffix.startswith("."):
                suffix = "." + suffix
            return host.endswith(suffix)

        if rule.type == "url":
            # Match a URL prefix: scheme+host must agree and path must be a prefix.
            return self._url_prefix_match(value, original_target)

        if rule.type == "cidr":
            # Only IP-literal hosts are matched. We deliberately do NOT resolve
            # hostnames to IPs here: DNS can change under our feet (and be abused
            # via rebinding), so resolving for scope decisions is unsafe.
            if not _looks_like_ip(host):
                return False
            try:
                return ip_address(host) in ip_network(value, strict=False)
            except ValueError:
                return False

        if rule.type == "regex":
            pattern = self._compiled.get(rule.value)
            return bool(pattern and pattern.fullmatch(host))

        return False

    @staticmethod
    def _url_prefix_match(rule_value: str, target: str) -> bool:
        """
        A 'url' rule matches when the target is the same scheme+host and its path
        starts with the rule's path. If the target is only a bare host (no
        scheme), a url rule cannot match it — we don't have enough information.
        """
        if "//" not in target:
            return False  # target is a bare host; url rule needs a full URL

        r = urlparse(rule_value)
        t = urlparse(target)

        if not r.hostname or not t.hostname:
            return False
        if r.hostname.lower() != t.hostname.lower():
            return False
        # If the rule pinned a scheme, honour it.
        if r.scheme and t.scheme and r.scheme.lower() != t.scheme.lower():
            return False

        rule_path = r.path or "/"
        target_path = t.path or "/"
        return target_path.startswith(rule_path)
