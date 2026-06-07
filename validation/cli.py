"""
validation/cli.py — the `bbp benchmark` command.

Runs every module against the lab, scores findings against the ground-truth
manifest, and prints precision/recall per module + per class, the gap log, and
the threshold recommendations. Persists each run for regression tracking.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from validation.gaps import build_gap_log
from validation.runner import BenchmarkRunner
from validation.threshold import recommend

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def benchmark(
        profile: Path = typer.Argument(Path("validation/lab_profile.local.yml"),
                                       help="Lab profile (targets to benchmark)."),
        manifest: Path = typer.Option(Path("validation/manifest.yml"), help="Ground-truth manifest."),
        db: Path = typer.Option(Path("data/benchmark.db"), help="Benchmark datastore (history)."),
        threshold: float = typer.Option(0.7, help="Confidence cutoff for auto-positive."),
    ) -> None:
        """Validate the modules against the lab and report precision/recall + gaps."""
        runner = BenchmarkRunner(str(profile), str(manifest), str(db), threshold)
        out = runner.run()
        metrics, results = out["metrics"], out["results"]

        # --- per-module metrics ---
        t1 = Table(title=f"Per-module results (threshold {threshold})")
        for col in ("Module", "TP", "FP", "FN", "Surfaced<T", "Precision", "Recall"):
            t1.add_column(col)
        for mod, m in sorted(metrics["by_module"].items()):
            if mod in ("?", "", "sqli"):  # no-module rows shown in the gap log
                continue
            t1.add_row(mod, str(m["tp"]), str(m["fp"]), str(m["fn"]), str(m["surfaced_low"]),
                       _pct(m["precision"]), _pct(m["recall"]))
        o = metrics["overall"]
        t1.add_row("[bold]OVERALL[/bold]", str(o["tp"]), str(o["fp"]), str(o["fn"]),
                   str(o["surfaced_low"]), _pct(o["precision"]), _pct(o["recall"]))
        console.print(t1)

        # --- per-class metrics ---
        t2 = Table(title="Per vuln-class")
        for col in ("Class", "TP", "FP", "FN", "Precision", "Recall"):
            t2.add_column(col)
        for cls, m in sorted(metrics["by_class"].items()):
            if m["tp"] + m["fp"] + m["fn"] + m["surfaced_low"] == 0:
                continue
            t2.add_row(cls, str(m["tp"]), str(m["fp"]), str(m["fn"] + m["surfaced_low"]),
                       _pct(m["precision"]), _pct(m["recall"]))
        console.print(t2)

        # --- gap log ---
        gaps = build_gap_log(results)
        if gaps:
            t3 = Table(title="Gap log (the module-improvement backlog)")
            for col in ("Class", "Target", "Location", "Action"):
                t3.add_column(col)
            for g in gaps:
                colour = {"fixable_tool_gap": "yellow", "tuning_gap": "cyan",
                          "inherently_manual": "dim"}.get(g.classification, "white")
                t3.add_row(f"[{colour}]{g.classification}[/]\n{g.vuln_class}", g.target,
                           g.location or "-", g.action)
            console.print(t3)

        # --- threshold recommendations ---
        recs = recommend(out["per_target"], out["manifest"])
        if recs:
            t4 = Table(title="Confidence-threshold recommendations (surfaced, not applied)")
            for col in ("Module", "Recommended", "F1", "Precision", "Recall"):
                t4.add_column(col)
            for r in recs:
                t4.add_row(r.module, str(r.recommended), str(r.f1), _pct(r.precision), _pct(r.recall))
            console.print(t4)

        # --- regression note ---
        from core.datastore import Datastore
        history = Datastore(str(db)).get_benchmark_runs()
        console.print(f"\n[green]Benchmark run {out['run_uid']} saved[/green] "
                      f"(run #{len(history)} in history — trend visible in the dashboard "
                      f"Validation view).")


def _pct(v) -> str:
    return f"{v:.0%}" if isinstance(v, (int, float)) else "—"
