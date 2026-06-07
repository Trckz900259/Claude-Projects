"""
runner.py — the fault-tolerant, queue-based, resumable run engine.

Given any Module, it:

  1. asks the module to build candidates from the shared inventory,
  2. enqueues them in the datastore (idempotently, so resume is safe),
  3. tests them CONCURRENTLY (bounded by the rate limiter), where each candidate
     is independent — one failure or one hit NEVER halts the run,
  4. records every finding (deduplicated, but every instance kept),
  5. completes across the WHOLE surface and returns consolidated stats.

Resumability: the work queue lives in SQLite. If a run is interrupted, re-run
with resume=True and it picks up the still-'pending' items, skipping anything
already 'done'.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.context import PlatformContext
from modules.base import Candidate, Module


class RunEngine:
    def __init__(
        self,
        ctx: PlatformContext,
        module: Module,
        logger: logging.Logger | None = None,
    ) -> None:
        self.ctx = ctx
        self.module = module
        self.ds = ctx.datastore
        self.log = logger or logging.getLogger("orchestrator")
        self._lock = threading.Lock()
        self._counts = {"tested": 0, "findings": 0, "failed": 0}

    def run(self, resume: bool = False, max_workers: int | None = None) -> dict:
        program_id = self.ctx.program_id
        module_name = self.module.name

        # --- pick or create a run ---
        run_id, run_uid = self._select_run(program_id, module_name, resume)
        self.log.info("Run %s (%s) for module %r", run_uid, "resumed" if resume else "new", module_name)

        # --- build + enqueue candidates (idempotent) ---
        candidates = self.module.build_candidates()
        for cand in candidates:
            self.ds.enqueue(run_id, module_name, cand.key(), {"data": cand.data})
        pending = self.ds.queue_stats(run_id).get("pending", 0)
        self.log.info("Candidates: %d built, %d pending in queue", len(candidates), pending)

        if pending == 0:
            self.ds.finish_run(run_id, status="done", stats=self._counts)
            return {**self._counts, "run_id": run_id, "run_uid": run_uid}

        # --- module setup (e.g. start blind-callback listener) ---
        try:
            self.module.setup()
        except Exception as exc:  # pragma: no cover - defensive
            self.log.warning("module.setup() failed: %s", exc)

        workers = max_workers or self.ctx.config.rate_limit.max_concurrency
        self.log.info("Testing with up to %d concurrent workers...", workers)

        # --- drain the queue concurrently ---
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._worker_loop, run_id, module_name) for _ in range(workers)]
            for f in as_completed(futures):
                # _worker_loop swallows its own errors; this is just a join.
                f.result()

        # --- module teardown ---
        try:
            self.module.teardown()
        except Exception as exc:  # pragma: no cover - defensive
            self.log.warning("module.teardown() failed: %s", exc)

        self.ds.finish_run(run_id, status="done", stats=self._counts)
        self.log.info("Run complete: %s", self._counts)
        return {**self._counts, "run_id": run_id, "run_uid": run_uid}

    # -- internals ---------------------------------------------------------
    def _select_run(self, program_id: int, module_name: str, resume: bool) -> tuple[int, str]:
        if resume:
            row = self.ds.query_one(
                "SELECT * FROM runs WHERE program_id = ? AND module = ? "
                "AND status IN ('running','paused') ORDER BY id DESC LIMIT 1",
                (program_id, module_name),
            )
            if row:
                return int(row["id"]), str(row["run_uid"])
            self.log.info("No resumable run found; starting a fresh one.")
        run_uid = uuid.uuid4().hex[:12]
        run_id = self.ds.start_run(program_id, run_uid, module=module_name)
        return run_id, run_uid

    def _worker_loop(self, run_id: int, module_name: str) -> None:
        """Each worker pulls candidates until the queue is empty."""
        while True:
            item = self.ds.next_pending(run_id, module_name)
            if item is None:
                return  # queue drained

            try:
                payload = json.loads(item["candidate"])
                cand = Candidate(module=module_name, data=payload.get("data", {}))
                findings = self.module.test_candidate(cand)  # the real work

                n = 0
                for finding in findings or []:
                    self.ds.record_finding(self.ctx.program_id, finding)
                    n += 1

                self.ds.mark_queue_item(item["id"], "done")
                with self._lock:
                    self._counts["tested"] += 1
                    self._counts["findings"] += n
            except Exception as exc:
                # A single candidate blowing up must NOT stop the run.
                self.log.warning("candidate %s failed: %s", item["candidate_key"], exc)
                self.ds.mark_queue_item(item["id"], "failed", error=str(exc))
                with self._lock:
                    self._counts["tested"] += 1
                    self._counts["failed"] += 1
