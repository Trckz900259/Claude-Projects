"""
report/cli.py — registers the `bbp report` command.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from core.context import PlatformContext
from core.exceptions import BBPlatformError
from report.generator import ReportGenerator

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def report(
        config: Path = typer.Argument(..., help="Path to a program YAML profile."),
        only_verified: bool = typer.Option(
            False, "--only-verified", help="Only report VERIFIED findings (recommended for submission)."
        ),
        no_pdf: bool = typer.Option(False, "--no-pdf", help="Skip PDF rendering (Markdown only)."),
        out: Path = typer.Option(Path("data/reports"), help="Output directory."),
        db: Path = typer.Option(Path("data/findings.db"), help="SQLite datastore path."),
    ) -> None:
        """Generate consultancy-grade reports (Markdown + PDF) for the findings."""
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)

        try:
            gen = ReportGenerator(ctx, out_dir=out)
            result = gen.generate_all(only_verified=only_verified, make_pdf=not no_pdf)
        finally:
            ctx.close()

        if result["reports"] == 0:
            console.print("[yellow]No findings to report yet. Run a scan first.[/yellow]")
            return
        console.print(
            f"[green]Generated {result['reports']} report(s)[/green] in [bold]{result['out_dir']}[/bold]\n"
            f"Consolidated report: [bold]{result['consolidated']}[/bold]"
        )
