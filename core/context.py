"""
context.py — the shared 'wiring' every command and module needs.

Building the foundation objects by hand each time (scope, rate limiter, HTTP
engine, datastore, program row) is repetitive and easy to get wrong. PlatformContext
does it once, from a config path, and hands back everything ready to use.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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
    http: HttpEngine
    rate_limiter: RateLimiter
    program_id: int

    @classmethod
    def from_config_path(
        cls,
        config_path: str | Path,
        db_path: str | Path = "data/findings.db",
    ) -> "PlatformContext":
        cfg = load_program_config(config_path)
        log = get_logger("context")

        rate_limiter = RateLimiter(
            requests_per_second=cfg.rate_limit.requests_per_second,
            per_host_rps=cfg.rate_limit.per_host_rps,
            max_concurrency=cfg.rate_limit.max_concurrency,
        )
        http = HttpEngine(
            scope=cfg.scope,
            rate_limiter=rate_limiter,
            http_config=cfg.http,
            logger=get_logger("http"),
        )
        datastore = Datastore(db_path=db_path)
        program_id = datastore.upsert_program(
            name=cfg.name,
            platform=cfg.platform,
            handle=cfg.handle,
            config_path=str(config_path),
        )
        log.info("Context ready for program %r (id=%d)", cfg.name, program_id)
        return cls(
            config=cfg,
            datastore=datastore,
            http=http,
            rate_limiter=rate_limiter,
            program_id=program_id,
        )

    def require_automated_scanning(self, action: str) -> None:
        """
        Call this before any ACTIVE step. If the program profile says automated
        scanning is not allowed, refuse — respecting program rules (safety #4).
        """
        if not self.config.rules.automated_scanning_allowed:
            raise ScanningNotPermittedError(self.config.name, action)

    def close(self) -> None:
        self.http.close()
        self.datastore.close()
