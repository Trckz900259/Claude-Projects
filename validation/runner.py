"""
runner.py — the benchmark runner.

Configures the platform to the lab only, runs each module against its target,
collects findings, matches them to the ground-truth manifest, scores them, and
persists the run (so later runs reveal REGRESSION).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

from core.context import PlatformContext
from core.datastore import Datastore
from modules.registry import get_module_class
from orchestrator.runner import RunEngine
from validation.scoring import aggregate, load_manifest, match_target
from validation.seeds import SEEDERS

log = logging.getLogger("benchmark")


@dataclass
class Target:
    name: str
    config: str
    module: str
    base_url: str
    seed: str
    kwargs: dict


class BenchmarkRunner:
    def __init__(self, profile_path: str, manifest_path: str = "validation/manifest.yml",
                 db_path: str = "data/benchmark.db", threshold: float = 0.7) -> None:
        prof = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8"))
        self.profile_name = prof.get("profile", "lab")
        self.targets = [Target(t["name"], t["config"], t["module"], t["base_url"],
                               t.get("seed", "recon"), t.get("kwargs", {}) or {})
                        for t in prof.get("targets", [])]
        self.manifest = load_manifest(manifest_path)
        self.db_path = db_path
        self.threshold = threshold

    def run(self) -> dict:
        ds = Datastore(self.db_path)
        ds.clear_scan_data()
        ds.clear_benchmark_results()
        run_uid = uuid.uuid4().hex[:12]
        run_id = ds.start_benchmark(run_uid, self.profile_name)
        ds.close()

        per_target: list[tuple] = []   # (target_name, [finding dicts])
        all_results = []
        for t in self.targets:
            log.info("Benchmarking target %r (%s -> %s)", t.name, t.module, t.base_url)
            findings = self._run_target(t)
            results = match_target(t.name, findings, self.manifest, self.threshold)
            all_results.extend(results)
            per_target.append((t.name, findings))

        metrics = aggregate(all_results)

        # Confidence-threshold recommendations (stored for the dashboard).
        from validation.threshold import recommend
        recs = recommend(per_target, self.manifest)
        metrics["threshold_recs"] = [
            {"module": r.module, "recommended": r.recommended, "f1": r.f1,
             "precision": r.precision, "recall": r.recall} for r in recs]

        # Persist results + metrics.
        ds = Datastore(self.db_path)
        for r in all_results:
            ds.add_benchmark_result(run_id, r.status, r.module, r.target, r.vuln_class,
                                    r.location, r.manifest_id, r.finding_id, r.confidence, r.note)
        ds.finish_benchmark(run_id, metrics)
        ds.close()

        return {"run_id": run_id, "run_uid": run_uid, "metrics": metrics,
                "results": all_results, "per_target": per_target, "manifest": self.manifest}

    def _run_target(self, t: Target) -> list[dict]:
        """Seed + scan one target; return its findings as plain dicts."""
        try:
            ctx = PlatformContext.from_config_path(t.config, db_path=self.db_path)
        except Exception as exc:
            log.warning("target %s: config error: %s", t.name, exc)
            return []
        try:
            seeder = SEEDERS.get(t.seed)
            if seeder:
                seeder(ctx, t.base_url)
            mod = get_module_class(t.module)(ctx, **t.kwargs)
            RunEngine(ctx, mod).run()
            findings = [dict(f) for f in ctx.datastore.get_findings(ctx.program_id)]
            log.info("  %s: %d finding(s)", t.name, len(findings))
            return findings
        except Exception as exc:
            log.warning("target %s: run failed: %s", t.name, exc)
            return []
        finally:
            ctx.close()
