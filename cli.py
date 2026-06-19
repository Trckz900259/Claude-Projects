"""
cli.py — the single command-line interface for the whole platform.

Run `bbp --help` (after `pip install -e .`) or `python -m cli --help`.

Commands grow with each build stage:
  Stage 1 (foundation):  doctor, validate-config, scope-check
  Stage 2 (recon):       recon
  Stage 3 (xss+verify):  scan, verify
  Stage 4 (reporting):   report
  Stage 5 (dashboard):   dashboard
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config import load_program_config
from core.exceptions import BBPlatformError
from core.logging_setup import configure_logging
from core.tooling import status_report

app = typer.Typer(
    add_completion=False,
    help="Bug Bounty Platform — modular, scope-safe security testing for AUTHORIZED programs.",
)
console = Console()


# ---------------------------------------------------------------------------
# Stage 1 commands
# ---------------------------------------------------------------------------
@app.command()
def doctor() -> None:
    """Check which external tools are installed (and how to install missing ones)."""
    rows = status_report()
    table = Table(title="External tool status", show_lines=False)
    table.add_column("Tool", style="bold")
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Purpose")

    missing = []
    for r in rows:
        ok = r["available"]
        status = "[green]✓ installed[/green]" if ok else "[red]✗ missing[/red]"
        table.add_row(r["name"], r["stage"], status, r["purpose"])
        if not ok:
            missing.append(r)

    console.print(table)
    if missing:
        console.print("\n[yellow]Missing tools — install with:[/yellow]")
        for r in missing:
            console.print(f"  • [bold]{r['name']}[/bold]: {r['install']}")
        console.print(
            "\nOr run the helper script: [bold]bash scripts/install_tools.sh[/bold]"
        )
    else:
        console.print("\n[green]All external tools are installed.[/green]")


@app.command("validate-config")
def validate_config(
    config: Path = typer.Argument(..., help="Path to a program YAML profile."),
) -> None:
    """Load a program profile, validate it, and print a human-readable summary."""
    try:
        cfg = load_program_config(config)
    except BBPlatformError as exc:
        console.print(Panel(str(exc), title="[red]Config error[/red]", border_style="red"))
        raise typer.Exit(code=1)

    lines = [
        f"[bold]Program:[/bold] {cfg.name}  ([italic]{cfg.platform}[/italic], handle: {cfg.handle})",
        f"[bold]Automated scanning allowed:[/bold] "
        + ("[green]yes[/green]" if cfg.rules.automated_scanning_allowed else "[red]no[/red]"),
        f"[bold]User-Agent:[/bold] {cfg.http.user_agent}",
        f"[bold]Rate limit:[/bold] {cfg.rate_limit.requests_per_second} req/s global, "
        f"{cfg.rate_limit.per_host_rps} req/s per host, "
        f"concurrency {cfg.rate_limit.max_concurrency}",
        f"[bold]interactsh domain:[/bold] {cfg.callback.interactsh_domain or '(not set)'}",
        "",
        "[bold]In-scope (allow-list):[/bold]",
    ]
    for r in cfg.scope.in_scope:
        lines.append(f"  [green]✓[/green] {r.type}: {r.value}")
    if cfg.scope.out_of_scope:
        lines.append("[bold]Out-of-scope (deny-list, always wins):[/bold]")
        for r in cfg.scope.out_of_scope:
            lines.append(f"  [red]✗[/red] {r.type}: {r.value}")

    console.print(Panel("\n".join(lines), title="[green]Config OK[/green]", border_style="green"))


@app.command("scope-check")
def scope_check(
    config: Path = typer.Argument(..., help="Path to a program YAML profile."),
    target: str = typer.Argument(..., help="A URL or host to test against the scope."),
) -> None:
    """
    Ask the scope enforcer whether a target is in scope — without making any
    network request. Great for understanding exactly what is and isn't allowed.
    """
    try:
        cfg = load_program_config(config)
    except BBPlatformError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    decision = cfg.scope.check(target)
    if decision.allowed:
        console.print(
            Panel(
                f"[green]IN SCOPE[/green] — {target}\n\nReason: {decision.reason}",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[red]OUT OF SCOPE — would be refused[/red]\n\n{target}\n\nReason: {decision.reason}",
                border_style="red",
            )
        )
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# Stage 2+ commands are registered here as they are built.
# ---------------------------------------------------------------------------
def _register_later_stages() -> None:
    """
    Import-and-register command groups that may pull in heavier dependencies.
    Done lazily so `bbp doctor` still works even if, say, Playwright isn't yet
    installed.
    """
    try:
        from recon.cli import register as register_recon

        register_recon(app)
    except Exception:
        pass
    try:
        from modules.cli import register as register_modules

        register_modules(app)
    except Exception:
        pass
    try:
        from modules.accesscontrol.cli import register as register_ac

        register_ac(app)
    except Exception:
        pass
    try:
        from report.cli import register as register_report

        register_report(app)
    except Exception:
        pass
    try:
        from dashboard.cli import register as register_dashboard

        register_dashboard(app)
    except Exception:
        pass
    try:
        from validation.cli import register as register_validation

        register_validation(app)
    except Exception:
        pass
    try:
        from core.gov_cli import register as register_gov

        register_gov(app)
    except Exception:
        pass


@app.callback()
def _main(ctx: typer.Context) -> None:
    """Set up logging before any command runs."""
    configure_logging()


_register_later_stages()


if __name__ == "__main__":
    app()
