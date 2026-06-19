"""
supervisor.py — the independent Safety Supervisor.

It can VETO or HALT activity, and it is deliberately NOT part of any agent: its
authoritative state (kill-switch, dry-run, halts, circuit breakers) lives in the
shared datastore, so the gateway reads it on every action and the dashboard can
flip it — an agent (Phase 2) cannot talk past it.

What it enforces:
  * Global KILL-SWITCH       — instant halt of all activity.
  * DRY-RUN                  — plan/log only, never execute.
  * CIRCUIT BREAKERS         — auto-halt on a 5xx burst, an error-rate spike, or
                               repeated scope near-misses (possible DoS/misbehaviour).
  * BLAST-RADIUS limits      — cap actions per target before a mandatory checkpoint.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

# Circuit-breaker thresholds (a target tripping any of these halts work on it).
FIVE_XX_THRESHOLD = 5         # a burst of 5xx -> possible DoS
ERROR_THRESHOLD = 10          # connection/other errors
SCOPE_NEAR_MISS_THRESHOLD = 3 # repeated out-of-scope attempts -> misbehaviour


@dataclass
class SupervisorDecision:
    allowed: bool
    reason: str = ""
    halted: bool = False


class SafetySupervisor:
    def __init__(self, datastore, program_id: int, max_actions_per_target: int = 200,
                 logger: logging.Logger | None = None) -> None:
        self.ds = datastore
        self.program_id = program_id
        self.max_actions_per_target = max_actions_per_target
        self.log = logger or logging.getLogger("supervisor")
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    # -- operator controls (shared, cross-process via gov_state) ----------
    def kill(self, reason: str = "manual kill-switch") -> None:
        self.ds.gov_set("kill_switch", "1")
        self.ds.gov_set("halted_reason", reason)
        self.log.warning("KILL-SWITCH ENGAGED: %s", reason)

    def clear_kill(self) -> None:
        self.ds.gov_set("kill_switch", "0")

    def is_killed(self) -> bool:
        return self.ds.gov_get("kill_switch", "0") == "1"

    def set_dry_run(self, on: bool) -> None:
        self.ds.gov_set("dry_run", "1" if on else "0")

    def is_dry_run(self) -> bool:
        return self.ds.gov_get("dry_run", "0") == "1"

    def halt(self, reason: str) -> None:
        self.ds.gov_set("halted", "1")
        self.ds.gov_set("halted_reason", reason)
        self.log.warning("ACTIVITY HALTED: %s", reason)

    def clear_halt(self) -> None:
        self.ds.gov_set("halted", "0")
        self.ds.reset_breakers(self.program_id)
        with self._lock:
            self._counts.clear()

    def is_halted(self) -> bool:
        return self.ds.gov_get("halted", "0") == "1"

    def status(self) -> dict:
        return {"kill_switch": self.is_killed(), "dry_run": self.is_dry_run(),
                "halted": self.is_halted(), "reason": self.ds.gov_get("halted_reason", ""),
                "breakers": [dict(r) for r in self.ds.breakers(self.program_id)]}

    # -- pre-action veto --------------------------------------------------
    def check(self, target: str) -> SupervisorDecision:
        if self.is_killed():
            return SupervisorDecision(False, "global kill-switch engaged", halted=True)
        if self.is_halted():
            return SupervisorDecision(False, f"activity halted: {self.ds.gov_get('halted_reason','')}",
                                      halted=True)
        if self.ds.breaker_tripped(self.program_id, target):
            return SupervisorDecision(False, f"circuit breaker tripped for {target}", halted=True)
        return SupervisorDecision(True, "ok")

    # -- bounded sequences (blast radius) ---------------------------------
    def count_action(self, target: str) -> SupervisorDecision:
        with self._lock:
            self._counts[target] = self._counts.get(target, 0) + 1
            n = self._counts[target]
        if n > self.max_actions_per_target:
            count, tripped = self.ds.breaker_bump(
                self.program_id, target, "blast_radius", 1,
                reason=f"exceeded {self.max_actions_per_target} actions (checkpoint required)")
            self.halt(f"blast-radius cap reached on {target} (checkpoint required)")
            return SupervisorDecision(False, "blast-radius cap reached (mandatory checkpoint)",
                                      halted=True)
        return SupervisorDecision(True, "ok")

    # -- anomaly feedback (after each response) ---------------------------
    def record_response(self, target: str, status_code: int, error: bool = False) -> None:
        if status_code and 500 <= status_code < 600:
            count, tripped = self.ds.breaker_bump(self.program_id, target, "5xx",
                                                  FIVE_XX_THRESHOLD, reason="burst of 5xx responses")
            if tripped:
                self.halt(f"5xx burst from {target} ({count}) — possible DoS; auto-halted")
        elif error:
            count, tripped = self.ds.breaker_bump(self.program_id, target, "error_rate",
                                                  ERROR_THRESHOLD, reason="error-rate spike")
            if tripped:
                self.halt(f"error-rate spike on {target} — auto-halted")

    def record_scope_near_miss(self, target: str) -> None:
        count, tripped = self.ds.breaker_bump(self.program_id, target, "scope_near_miss",
                                              SCOPE_NEAR_MISS_THRESHOLD,
                                              reason="repeated out-of-scope attempts")
        if tripped:
            self.halt(f"repeated scope near-misses toward {target} — auto-halted")
