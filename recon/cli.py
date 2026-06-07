"""
recon/cli.py — registers the `bbp recon` command on the main CLI app.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.context import PlatformContext
from core.exceptions import BBPlatformError
from recon.pipeline import ReconPipeline

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def recon(
        config: Path = typer.Argument(..., help="Path to a program YAML profile."),
        depth: int = typer.Option(2, help="Crawl depth for katana (active)."),
        arjun_sample: int = typer.Option(12, help="How many endpoints to run arjun on."),
        seed_url: list[str] = typer.Option(
            [], "--seed-url", help="Explicit in-scope URL to crawl (repeatable)."
        ),
        no_subfinder: bool = typer.Option(False, "--no-subfinder", help="Skip subdomain enumeration."),
        no_httpx: bool = typer.Option(False, "--no-httpx", help="Skip live-host probing."),
        no_gau: bool = typer.Option(False, "--no-gau", help="Skip archive URL harvesting."),
        no_katana: bool = typer.Option(False, "--no-katana", help="Skip active crawl."),
        no_arjun: bool = typer.Option(False, "--no-arjun", help="Skip hidden-parameter discovery."),
        db: Path = typer.Option(Path("data/findings.db"), help="SQLite datastore path."),
    ) -> None:
        """
        Run reconnaissance and populate the shared inventory.

        Passive steps always run; active steps (httpx/katana/arjun) run only if
        the program profile allows automated scanning.
        """
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1)

        try:
            pipeline = ReconPipeline(ctx)
            stats = pipeline.run(
                crawl_depth=depth,
                arjun_sample=arjun_sample,
                seed_urls=list(seed_url),
                do_subfinder=not no_subfinder,
                do_httpx=not no_httpx,
                do_gau=not no_gau,
                do_katana=not no_katana,
                do_arjun=not no_arjun,
            )
        finally:
            ctx.close()

        table = Table(title=f"Recon results — {ctx.config.name}")
        table.add_column("Inventory", style="bold")
        table.add_column("Count", justify="right")
        table.add_row("Subdomains found", str(stats["subdomains"]))
        table.add_row("Live hosts", str(stats["live_hosts"]))
        table.add_row("URLs harvested", str(stats["urls"]))
        table.add_row("Query parameters", str(stats["parameters"]))
        table.add_row("Hidden params (arjun)", str(stats["hidden_params"]))
        console.print(table)
        console.print(
            f"\nInventory saved to [bold]{db}[/bold]. "
            f"Next: run an XSS scan with [bold]bbp scan {config} --module xss[/bold]"
        )
