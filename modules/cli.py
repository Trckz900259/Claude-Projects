"""
modules/cli.py — registers the `bbp scan` and `bbp callbacks` commands.
"""

from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.context import PlatformContext
from core.exceptions import BBPlatformError, ScanningNotPermittedError
from modules.registry import available_modules, get_module_class
from modules.xss.blind import InteractshListener
from orchestrator.runner import RunEngine

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def scan(
        config: Path = typer.Argument(..., help="Path to a program YAML profile."),
        module: str = typer.Option("xss", "--module", "-m", help=f"One of: {', '.join(available_modules())}"),
        resume: bool = typer.Option(False, "--resume", help="Resume an interrupted run."),
        no_dalfox: bool = typer.Option(False, "--no-dalfox", help="Don't invoke dalfox."),
        no_blind: bool = typer.Option(False, "--no-blind", help="Don't inject blind/OOB payloads."),
        record_video: bool = typer.Option(False, "--video", help="Record short PoC videos (slower)."),
        db: Path = typer.Option(Path("data/findings.db"), help="SQLite datastore path."),
    ) -> None:
        """Run a vulnerability module across the inventory, fault-tolerantly."""
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)

        try:
            module_cls = get_module_class(module)
        except KeyError as exc:
            console.print(f"[red]{exc}[/red]")
            ctx.close()
            raise typer.Exit(code=1)

        kwargs = {}
        if module == "xss":
            kwargs = dict(use_dalfox=not no_dalfox, use_blind=not no_blind, record_video=record_video)

        mod = module_cls(ctx, **kwargs)
        engine = RunEngine(ctx, mod)
        try:
            stats = engine.run(resume=resume)
        except ScanningNotPermittedError as exc:
            console.print(
                f"[red]{exc}[/red]\n\nSet [bold]rules.automated_scanning_allowed: true[/bold] "
                f"in {config} only if the program permits automation."
            )
            ctx.close()
            raise typer.Exit(code=2)

        _print_scan_summary(ctx, stats, db)
        ctx.close()

    @app.command()
    def callbacks(
        config: Path = typer.Argument(..., help="Path to a program YAML profile."),
        db: Path = typer.Option(Path("data/findings.db"), help="SQLite datastore path."),
    ) -> None:
        """
        Run the interactsh listener on its own and keep recording blind-XSS
        callbacks (which can arrive hours after a scan). Press Ctrl-C to stop.
        """
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)

        listener = InteractshListener(ctx.config, ctx.datastore, ctx.program_id)
        if not listener.start():
            console.print("[red]Could not start interactsh-client (is it installed?).[/red]")
            ctx.close()
            raise typer.Exit(code=1)

        console.print(
            f"[green]Listening for blind-XSS callbacks[/green] on "
            f"[bold]{listener.session.domain or '(domain registering...)'}[/bold]. Ctrl-C to stop."
        )
        try:
            while True:
                time.sleep(2)
        except KeyboardInterrupt:
            console.print("\nStopping listener.")
        finally:
            listener.stop()
            ctx.close()


def _print_scan_summary(ctx: PlatformContext, stats: dict, db: Path) -> None:
    ds, pid = ctx.datastore, ctx.program_id
    table = Table(title=f"Scan results — {ctx.config.name}")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Candidates tested", str(stats.get("tested", 0)))
    table.add_row("Findings recorded", str(stats.get("findings", 0)))
    table.add_row("Failures (skipped)", str(stats.get("failed", 0)))
    console.print(table)

    rows = ds.query(
        "SELECT severity, status, COUNT(*) n FROM findings WHERE program_id = ? "
        "GROUP BY severity, status ORDER BY severity", (pid,),
    )
    if rows:
        breakdown = Table(title="Findings by severity / status")
        breakdown.add_column("Severity")
        breakdown.add_column("Status")
        breakdown.add_column("Count", justify="right")
        for r in rows:
            breakdown.add_row(r["severity"], r["status"], str(r["n"]))
        console.print(breakdown)

    verified = ds.query_one(
        "SELECT COUNT(*) n FROM findings WHERE program_id = ? AND status = 'verified'", (pid,)
    )
    console.print(
        f"\n[bold]{verified['n'] if verified else 0}[/bold] verified finding(s). "
        f"Datastore: [bold]{db}[/bold]\n"
        f"Next: generate reports with [bold]bbp report {ctx.config.source_path}[/bold]"
    )
