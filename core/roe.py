"""
roe.py — the Rules-of-Engagement (RoE) contract.

A per-program authorization contract: scope, allowed techniques, rate limits,
time windows, and no-go assets. The Action Gateway enforces it as a HARD
contract. The rule the whole backbone rests on:

    No RoE loaded  ==  the gateway refuses ALL actions for that program.

We build the RoE from the program profile (reusing its scope/rules/rate-limit)
plus an optional `roe:` section that adds the extra contract fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.config import ProgramConfig
from core.scope import ScopeEnforcer, ScopeRule, host_of


@dataclass
class RoEDecision:
    allowed: bool
    reason: str


@dataclass
class RoE:
    program: str
    scope: ScopeEnforcer
    automated_scanning_allowed: bool
    ai_testing_allowed: bool
    allowed_techniques: set[str]          # {"*"} = all
    no_go: list[ScopeRule] = field(default_factory=list)
    time_windows: list[tuple[int, int]] = field(default_factory=list)  # (start_h, end_h) UTC
    max_actions_per_target: int = 200     # bounded-sequence cap
    rps: float = 2.0
    per_host_rps: float = 1.0
    max_concurrency: int = 5
    loaded: bool = True

    # -- target checks -----------------------------------------------------
    def is_no_go(self, target: str) -> bool:
        host = host_of(target)
        if not host:
            return False
        deny = ScopeEnforcer(in_scope=self.no_go) if self.no_go else None
        return bool(deny and deny.check(target).allowed)

    def allows_target(self, target: str) -> RoEDecision:
        if self.is_no_go(target):
            return RoEDecision(False, "target is on the RoE NO-GO list")
        d = self.scope.check(target)
        if not d.allowed:
            return RoEDecision(False, f"out of scope: {d.reason}")
        return RoEDecision(True, "in scope")

    def allows_technique(self, technique: str) -> bool:
        return "*" in self.allowed_techniques or technique in self.allowed_techniques

    def within_time_window(self, now: datetime | None = None) -> bool:
        if not self.time_windows:
            return True  # no restriction configured -> 24/7
        now = now or datetime.now(tz=timezone.utc)
        h = now.hour
        return any(s <= h < e for s, e in self.time_windows)


def _parse_windows(raw) -> list[tuple[int, int]]:
    out = []
    for w in raw or []:
        try:
            a, b = str(w).split("-")
            out.append((int(a.split(":")[0]), int(b.split(":")[0])))
        except Exception:
            continue
    return out


def load_roe(config: ProgramConfig) -> RoE:
    """Build the RoE for a program from its profile (+ optional `roe:` section)."""
    raw = (config.raw.get("roe", {}) or {})
    techniques = raw.get("allowed_techniques")
    allowed = set(techniques) if isinstance(techniques, list) and techniques else {"*"}
    no_go = []
    for entry in (raw.get("no_go_assets") or []):
        try:
            if isinstance(entry, str):
                no_go.append(ScopeRule("domain", entry))
            else:
                no_go.append(ScopeRule(str(entry.get("type", "domain")), str(entry["value"])))
        except Exception:
            continue
    return RoE(
        program=config.name,
        scope=config.scope,
        automated_scanning_allowed=config.rules.automated_scanning_allowed,
        ai_testing_allowed=bool(raw.get("ai_testing_allowed", False)),
        allowed_techniques=allowed,
        no_go=no_go,
        time_windows=_parse_windows(raw.get("time_windows")),
        max_actions_per_target=int(raw.get("max_actions_per_target", 200)),
        rps=config.rate_limit.requests_per_second,
        per_host_rps=config.rate_limit.per_host_rps,
        max_concurrency=config.rate_limit.max_concurrency,
        loaded=True,
    )
