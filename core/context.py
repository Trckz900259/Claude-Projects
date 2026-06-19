"""
context.py — the shared 'wiring' every command and module needs.

As of Phase 1 this also wires the SAFETY & GOVERNANCE BACKBONE: it builds the one
Action Gateway and makes `ctx.http` a gateway-backed facade, so EVERY existing
module's HTTP (and, via ctx.gateway.run_tool, every tool) is funnelled through the
single policy enforcement point — without changing the modules themselves.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.config import ProgramConfig, load_program_config
from core.datastore import Datastore
from core.exceptions import ScanningNotPermittedError
from core.http_engine import HttpEngine
from core.logging_setup import get_logger
from core.ratelimit import RateLimiter


@dataclass
class PlatformContext:
    """Everything a run needs, built from one program profile."""

    config: ProgramConfig
    datastore: Datastore
    http: Any                 # GatewayHttp facade (same interface as HttpEngine)
    rate_limiter: RateLimiter
    program_id: int
    gateway: Any = None
    supervisor: Any = None
    audit: Any = None
    roe: Any = None
    usage: Any = None
    approvals: Any = None
    redactor: Any = None
    _http_engine: Any = field(default=None, repr=False)

    @classmethod
    def from_config_path(
        cls,
        config_path: str | Path,
        db_path: str | Path = "data/findings.db",
    ) -> "PlatformContext":
        cfg = load_program_config(config_path)
        log = get_logger("context")
        data_dir = Path(db_path).parent

        rate_limiter = RateLimiter(
            requests_per_second=cfg.rate_limit.requests_per_second,
            per_host_rps=cfg.rate_limit.per_host_rps,
            max_concurrency=cfg.rate_limit.max_concurrency,
        )
        http_engine = HttpEngine(scope=cfg.scope, rate_limiter=rate_limiter,
                                 http_config=cfg.http, logger=get_logger("http"))
        datastore = Datastore(db_path=db_path)
        program_id = datastore.upsert_program(
            name=cfg.name, platform=cfg.platform, handle=cfg.handle,
            config_path=str(config_path))

        # --- governance backbone ---
        from core.approval import ApprovalQueue
        from core.audit import AuditTrail
        from core.gateway import ActionGateway, GatewayHttp, Permissions
        from core.governance import Redactor, SecretsStore, get_data_cipher
        from core.injection import InjectionDetector
        from core.roe import load_roe
        from core.supervisor import SafetySupervisor
        from core.usage import UsageGovernor

        secrets = SecretsStore()
        # Ensures an at-rest key exists; we derive a separate HMAC key for the audit.
        get_data_cipher(secrets, key_path=str(data_dir / ".data_key"))
        data_key = (data_dir / ".data_key").read_text().strip() if (data_dir / ".data_key").exists() \
            else "dev-key"
        audit_key = hashlib.sha256(("audit:" + data_key).encode()).digest()

        redactor = Redactor()
        roe = load_roe(cfg)
        supervisor = SafetySupervisor(datastore, program_id,
                                      max_actions_per_target=roe.max_actions_per_target,
                                      logger=get_logger("supervisor"))
        audit = AuditTrail(audit_key, db_path=str(data_dir / "audit.db"), redactor=redactor)
        approvals = ApprovalQueue(datastore, program_id, redactor=redactor)
        injection = InjectionDetector()

        ucfg = cfg.raw.get("usage", {}) or {}
        usage = UsageGovernor(
            daily_budget=float(ucfg.get("daily_budget_tokens", 0)),
            rolling_budget=float(ucfg.get("rolling_budget_tokens", 0)),
            rolling_window_seconds=int(ucfg.get("rolling_window_seconds", 3600)),
            reserve_fraction=float(ucfg.get("reserve_fraction", 0.15)),
            state_path=str(data_dir / "usage.json"))

        gov = cfg.raw.get("governance", {}) or {}
        gateway = ActionGateway(
            http_engine=http_engine, roe=roe, supervisor=supervisor, audit=audit,
            permissions=Permissions(), injection=injection, approvals=approvals,
            usage=usage, config=cfg, datastore=datastore, program_id=program_id,
            redactor=redactor,
            require_approval_for_state_changing=bool(gov.get("require_approval_for_state_changing", False)),
            logger=get_logger("gateway"))

        http = GatewayHttp(gateway)
        log.info("Context ready for program %r (id=%d) — gateway + governance active",
                 cfg.name, program_id)
        return cls(
            config=cfg, datastore=datastore, http=http, rate_limiter=rate_limiter,
            program_id=program_id, gateway=gateway, supervisor=supervisor, audit=audit,
            roe=roe, usage=usage, approvals=approvals, redactor=redactor,
            _http_engine=http_engine)

    def require_automated_scanning(self, action: str) -> None:
        if not self.config.rules.automated_scanning_allowed:
            raise ScanningNotPermittedError(self.config.name, action)

    def session_manager(self):
        from core.identity import SessionManager, load_identities
        profiles = load_identities(self.config)
        sm = SessionManager(self.http, profiles, logger=get_logger("identity"))
        sm.persist(self.datastore, self.program_id)
        return sm

    def close(self) -> None:
        try:
            self.http.close()
        except Exception:
            pass
        if self.audit is not None:
            self.audit.close()
        self.datastore.close()
