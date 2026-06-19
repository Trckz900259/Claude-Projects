"""
approval.py — the human-in-the-loop approval gate (a general primitive).

Any action can be tagged "requires approval". Instead of auto-executing, the
gateway SUBMITS it here, which pauses it and surfaces it in the dashboard for an
explicit approve/deny. The action only proceeds on approval. Used now for
high-impact / state-changing actions, and later for final report submission.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass


@dataclass
class ApprovalResult:
    status: str          # pending | approved | denied | timeout
    approval_id: int


class ApprovalQueue:
    def __init__(self, datastore, program_id: int, redactor=None,
                 logger: logging.Logger | None = None) -> None:
        self.ds = datastore
        self.program_id = program_id
        self.redactor = redactor
        self.log = logger or logging.getLogger("approval")

    def submit(self, actor: str, kind: str, target: str, summary: str,
               impact: str, params: dict | None = None) -> int:
        """Queue an action for approval. Returns the approval id (status=pending)."""
        params = params or {}
        if self.redactor is not None:
            try:
                params = self.redactor.redact_dict(params)
            except Exception:
                params = {}
        aid = self.ds.add_approval(self.program_id, actor, kind, target, summary, impact, params)
        self.log.info("APPROVAL REQUIRED (#%d): %s %s [%s] — %s", aid, kind, target, impact, summary)
        return aid

    def status(self, approval_id: int) -> str:
        row = self.ds.get_approval(approval_id)
        return row["status"] if row else "denied"

    def approve(self, approval_id: int, by: str = "operator") -> None:
        self.ds.decide_approval(approval_id, "approved", by)

    def deny(self, approval_id: int, by: str = "operator") -> None:
        self.ds.decide_approval(approval_id, "denied", by)

    def pending(self):
        return self.ds.get_approvals(self.program_id, status="pending")

    def wait(self, approval_id: int, timeout: float = 0.0, poll: float = 0.5) -> ApprovalResult:
        """
        Block until the action is approved/denied (or timeout). timeout=0 returns
        immediately with the current status (non-blocking submit-and-continue).
        """
        deadline = time.time() + timeout
        while True:
            st = self.status(approval_id)
            if st in ("approved", "denied"):
                return ApprovalResult(st, approval_id)
            if timeout <= 0 or time.time() >= deadline:
                return ApprovalResult("pending" if timeout <= 0 else "timeout", approval_id)
            time.sleep(poll)
