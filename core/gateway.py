"""
gateway.py — the ONE mandatory Action Gateway (policy enforcement point).

Every action that touches a target or runs a tool — from today's modules and
(Phase 2) the agent — passes through here. Nothing reaches the network or runs a
tool except through this chokepoint. That single funnel is what makes autonomy
safe later.

Pipeline for every action (each step can deny/escalate; all decisions audited):

  1. SUPERVISOR   — kill-switch / global halt / tripped circuit breaker?
  2. RoE          — loaded? in scope & not no-go? technique allowed? time window?
                    automated-scanning / AI-testing permitted?
  3. CLASSIFIER   — read-only/minimal -> allow; state-changing -> (maybe) approve;
                    destructive -> BLOCK.
  4. PERMISSIONS  — just-in-time: is this tool granted for the caller's objective?
  5. BLAST RADIUS — bounded sequences: cap actions per target before a checkpoint.
  6. USAGE        — within the budget (the 85% cap)?
  7. APPROVAL     — if tagged/escalated, pause for human approve/deny.
  8. DRY-RUN      — if on, log the intended action and DO NOT execute.
  9. EXECUTE      — HTTP via the scope+rate+UA engine, or a tool via subprocess.
 10. POST         — feed anomalies to the supervisor; scan the response for
                    injection (DATA only, never instructions); audit the outcome.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field

from core.exceptions import BBPlatformError, OutOfScopeError
from core.http_engine import HttpEngine, HttpResult


class GatewayDenied(BBPlatformError):
    """An action was refused by the gateway (rules/permissions/supervisor/usage)."""


class ApprovalRequired(BBPlatformError):
    """An action is paused awaiting human approval. Carries the approval id."""
    def __init__(self, approval_id: int, reason: str) -> None:
        self.approval_id = approval_id
        super().__init__(f"approval required (#{approval_id}): {reason}")


# --- safety classifier ------------------------------------------------------
_DESTRUCTIVE_HTTP = {"DELETE"}
_STATECHANGING_HTTP = {"POST", "PUT", "PATCH"}
_DESTRUCTIVE_TOOL_FLAGS = ("--os-shell", "--os-pwn", "--dump-all", "--dump", "--delete",
                           "--drop", "--file-write", "--sql-shell")


def classify_http(method: str) -> str:
    m = (method or "GET").upper()
    if m in _DESTRUCTIVE_HTTP:
        return "destructive"
    if m in _STATECHANGING_HTTP:
        return "state_changing"
    return "read_only"


def classify_tool(tool: str, argv: list[str]) -> str:
    flags = " ".join(argv or [])
    if any(f in flags for f in _DESTRUCTIVE_TOOL_FLAGS):
        return "destructive"
    if tool in ("sqlmap",):
        return "state_changing"   # data-extraction capable -> flag/escalate
    return "read_only"


# --- just-in-time permissions ----------------------------------------------
class Permissions:
    """
    Grant tools per objective, checked at the moment of use, never permanently.
    Default posture (Phase 1, trusted modules): if an actor has NO grants, it is
    permitted (so existing modules keep working). Once any grant is issued for an
    actor (Phase 2 agent), it is enforced strictly: only granted, unexpired tools.
    """
    def __init__(self) -> None:
        self._grants: dict[str, dict[str, float]] = {}  # actor -> {tool: expiry_ts}

    def grant(self, actor: str, tools: list[str], ttl: float = 300.0) -> None:
        exp = time.time() + ttl
        self._grants.setdefault(actor, {}).update({t: exp for t in tools})

    def revoke(self, actor: str) -> None:
        self._grants.pop(actor, None)

    def check(self, actor: str, tool: str) -> bool:
        grants = self._grants.get(actor)
        if not grants:
            return True  # no policy issued for this actor -> default-permit
        exp = grants.get(tool)
        return bool(exp and exp >= time.time())


@dataclass
class ToolResult:
    tool: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    executed: bool = True
    error: str = ""


@dataclass
class GatewayResult:
    """Wraps an executed result with the gateway's decision metadata."""
    decision: str                    # allow | deny | dry_run | escalate
    reason: str = ""
    impact: str = ""
    http: HttpResult | None = None
    tool: ToolResult | None = None
    injection_flagged: bool = False


class ActionGateway:
    def __init__(self, *, http_engine: HttpEngine, roe, supervisor, audit,
                 permissions: Permissions, injection, approvals, usage, config,
                 datastore, program_id: int, redactor=None,
                 require_approval_for_state_changing: bool = False,
                 logger: logging.Logger | None = None) -> None:
        self.http_engine = http_engine
        self.roe = roe
        self.supervisor = supervisor
        self.audit = audit
        self.permissions = permissions
        self.injection = injection
        self.approvals = approvals
        self.usage = usage
        self.config = config
        self.ds = datastore
        self.program_id = program_id
        self.redactor = redactor
        self.require_approval_state = require_approval_for_state_changing
        self.log = logger or logging.getLogger("gateway")

    # -- audit helper -----------------------------------------------------
    def _audit(self, actor, target, kind, params, decision, reason, impact):
        try:
            self.audit.append(program=self.config.name, actor=actor, target=target,
                              kind=kind, params=params, decision=decision,
                              reason=reason, impact=impact)
        except Exception as exc:  # auditing must never crash the run
            self.log.debug("audit append failed: %s", exc)

    # -- the shared authorization pipeline --------------------------------
    def _authorize(self, *, actor, objective, target, kind, technique, tool,
                   impact, requires_approval, params, active: bool, approval_id=None):
        """Run the governance checks. Returns ('allow'|'dry_run', reason) or raises."""
        # 0) RoE must be loaded — no RoE = refuse all.
        if self.roe is None or not getattr(self.roe, "loaded", False):
            self._audit(actor, target, kind, params, "deny", "no RoE loaded", impact)
            raise GatewayDenied("no Rules-of-Engagement loaded for this program")

        # 1) Supervisor (kill / halt / breaker).
        sd = self.supervisor.check(target)
        if not sd.allowed:
            self._audit(actor, target, kind, params, "deny", sd.reason, impact)
            raise GatewayDenied(sd.reason)

        # 2) RoE: scope + no-go.
        td = self.roe.allows_target(target)
        if not td.allowed:
            self.supervisor.record_scope_near_miss(target)
            self._audit(actor, target, kind, params, "deny", td.reason, impact)
            raise OutOfScopeError(target, td.reason)
        # 2b) technique / time-window / rules.
        if technique and not self.roe.allows_technique(technique):
            self._audit(actor, target, kind, params, "deny", f"technique {technique} not allowed", impact)
            raise GatewayDenied(f"technique '{technique}' is not in the RoE allowed list")
        if not self.roe.within_time_window():
            self._audit(actor, target, kind, params, "deny", "outside RoE time window", impact)
            raise GatewayDenied("outside the RoE testing time window")
        if active and not self.roe.automated_scanning_allowed:
            self._audit(actor, target, kind, params, "deny", "automated scanning disabled", impact)
            raise GatewayDenied("automated scanning is not permitted for this program")
        if actor == "agent" and not self.roe.ai_testing_allowed:
            self._audit(actor, target, kind, params, "deny", "AI testing disabled", impact)
            raise GatewayDenied("AI testing is not permitted for this program")

        # 3) Classifier: block destructive outright.
        if impact == "destructive":
            self._audit(actor, target, kind, params, "deny", "destructive action blocked", impact)
            raise GatewayDenied("destructive / state-destroying action is blocked")

        # 4) Just-in-time permissions.
        perm_key = tool or technique or kind
        if not self.permissions.check(actor, perm_key):
            self._audit(actor, target, kind, params, "deny", f"tool '{perm_key}' not granted", impact)
            raise GatewayDenied(f"'{perm_key}' is not granted to '{actor}' for this objective")

        # 5) Blast radius / bounded sequences.
        bd = self.supervisor.count_action(target)
        if not bd.allowed:
            self._audit(actor, target, kind, params, "deny", bd.reason, impact)
            raise GatewayDenied(bd.reason)

        # 6) Usage budget (the 85% cap).
        ud = self.usage.check()
        if not ud.allowed:
            self._audit(actor, target, kind, params, "deny", f"usage halt: {ud.reason}", impact)
            raise GatewayDenied(f"usage budget halt: {ud.reason}")
        self.usage.record(requests=1)

        # 7) Approval gate (tagged, or state-changing when configured).
        needs_approval = requires_approval or (impact == "state_changing" and self.require_approval_state)
        if needs_approval:
            if approval_id is not None:
                # Re-presenting a previously-queued action with its handle.
                st = self.approvals.status(approval_id)
                if st == "approved":
                    self._audit(actor, target, kind, params, "allow", f"approved (#{approval_id})", impact)
                elif st == "denied":
                    self._audit(actor, target, kind, params, "deny", f"denied (#{approval_id})", impact)
                    raise GatewayDenied(f"action denied by operator (#{approval_id})")
                else:
                    raise ApprovalRequired(approval_id, f"{kind} {target} ({impact}) still pending")
            else:
                # First time: queue it and PAUSE (do not execute).
                aid = self.approvals.submit(actor, kind, target,
                                            summary=f"{kind} {target}", impact=impact, params=params)
                self._audit(actor, target, kind, params, "escalate", f"awaiting approval (#{aid})", impact)
                raise ApprovalRequired(aid, f"{kind} {target} ({impact})")

        # 8) Dry-run.
        if self.supervisor.is_dry_run():
            self._audit(actor, target, kind, params, "dry_run", "planned (dry-run)", impact)
            return "dry_run", "dry-run: not executed"

        return "allow", "authorized"

    # -- HTTP path --------------------------------------------------------
    def http_request(self, method: str, url: str, *, headers=None, params=None,
                     data=None, json=None, timeout=None, actor: str = "module",
                     objective: str = "scan", technique: str = "",
                     requires_approval: bool = False, approval_id=None) -> HttpResult:
        impact = classify_http(method)
        active = impact != "read_only" or True  # any outbound request is "active"
        p = {"method": method, "url": url, "headers": headers, "body": data or json}
        decision, reason = self._authorize(
            actor=actor, objective=objective, target=url, kind="http",
            technique=technique, tool="", impact=impact, requires_approval=requires_approval,
            params=p, active=active, approval_id=approval_id)

        if decision == "dry_run":
            return HttpResult(url=url, method=method.upper(), status_code=0,
                              request_headers=headers or {}, request_body="",
                              response_headers={}, text="[dry-run: not executed]",
                              elapsed_ms=0.0, final_url=url, error="dry_run")

        # EXECUTE via the scope+rate+UA engine (defence-in-depth: it re-checks scope).
        res = self.http_engine.request(method, url, headers=headers, params=params,
                                       data=data, json=json, timeout=timeout)
        # POST: feed anomalies to the supervisor; scan response as DATA only.
        self.supervisor.record_response(url, res.status_code, error=bool(res.error))
        flagged = self._scan_response(url, res)
        self._audit(actor, url, "http", {"method": method, "url": url, "status": res.status_code},
                    "allow", reason, impact)
        return res

    def _scan_response(self, source: str, res: HttpResult) -> bool:
        verdict = self.injection.scan(res.text or "", source=source)
        if verdict.flagged:
            snippet = res.text[:400] if res.text else ""
            if self.redactor is not None:
                snippet = self.redactor.redact(snippet)
            self.ds.quarantine_injection(self.program_id, source, verdict.severity,
                                         verdict.patterns, snippet)
            self._audit("detector", source, "injection", {"patterns": verdict.patterns},
                        "quarantine", verdict.summary, verdict.severity)
            self.log.warning("INJECTION FLAGGED from %s: %s", source, verdict.patterns)
        return verdict.flagged

    # -- tool path --------------------------------------------------------
    def run_tool(self, tool: str, argv: list[str], target: str, *, actor: str = "module",
                 objective: str = "scan", technique: str = "", stdin: str | None = None,
                 timeout: int = 180, requires_approval: bool = False, approval_id=None) -> ToolResult:
        impact = classify_tool(tool, argv)
        p = {"tool": tool, "argv": argv, "target": target}
        decision, reason = self._authorize(
            actor=actor, objective=objective, target=target, kind="tool",
            technique=technique, tool=tool, impact=impact, requires_approval=requires_approval,
            params=p, active=True, approval_id=approval_id)

        if decision == "dry_run":
            return ToolResult(tool=tool, returncode=0, stdout="", executed=False,
                              error="dry_run")
        try:
            proc = subprocess.run([tool, *argv], input=stdin, capture_output=True,
                                  text=True, timeout=timeout)
            result = ToolResult(tool, proc.returncode, proc.stdout or "", proc.stderr or "")
        except FileNotFoundError:
            result = ToolResult(tool, 127, executed=False, error="tool not found")
        except subprocess.TimeoutExpired:
            result = ToolResult(tool, 124, executed=False, error="timeout")
        except Exception as exc:
            result = ToolResult(tool, 1, executed=False, error=str(exc))
        self._audit(actor, target, "tool", {"tool": tool, "rc": result.returncode},
                    "allow", reason, impact)
        return result


# --- drop-in HTTP facade so existing modules route through the gateway -------
class GatewayHttp:
    """
    Presents the same interface as HttpEngine (get/post/head/request/scope/close)
    but routes every call through the ActionGateway. ctx.http becomes one of
    these, so the existing modules are gated WITHOUT any change to their code.
    """
    def __init__(self, gateway: ActionGateway) -> None:
        self._gw = gateway
        self.scope = gateway.roe.scope if gateway.roe else None

    def request(self, method, url, **kw) -> HttpResult:
        # absorb HttpEngine-only kwargs vs gateway kwargs
        gw_kw = {k: kw.pop(k) for k in ("actor", "objective", "technique", "requires_approval")
                 if k in kw}
        return self._gw.http_request(method, url, **kw, **gw_kw)

    def get(self, url, **kw) -> HttpResult:
        return self.request("GET", url, **kw)

    def post(self, url, **kw) -> HttpResult:
        return self.request("POST", url, **kw)

    def head(self, url, **kw) -> HttpResult:
        return self.request("HEAD", url, **kw)

    def close(self) -> None:
        self._gw.http_engine.close()
