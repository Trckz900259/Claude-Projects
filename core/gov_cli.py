"""
gov_cli.py — operator controls for the safety & governance backbone.

  bbp safety <config>                 show kill-switch/dry-run/halt/breakers/usage
  bbp kill <config>                   engage the global kill-switch (halt all)
  bbp resume <config>                 clear the kill-switch + halt + breakers
  bbp dry-run <config> --on/--off     plan-and-log only (no execution)
  bbp approvals <config> [--approve N | --deny N]   list / decide the approval queue
  bbp audit-verify <config>           verify the tamper-evident audit chain
  bbp retention <config> --days N     purge sensitive captured data older than N days
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.context import PlatformContext
from core.exceptions import BBPlatformError

console = Console()
DB = typer.Option(Path("data/findings.db"), help="SQLite datastore path.")


def _ctx(config, db):
    try:
        return PlatformContext.from_config_path(config, db_path=db)
    except BBPlatformError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


def register(app: typer.Typer) -> None:
    @app.command()
    def safety(config: Path = typer.Argument(...), db: Path = DB) -> None:
        """Show the live safety & governance status."""
        ctx = _ctx(config, db)
        s = ctx.supervisor.status()
        console.print(f"[bold]Program:[/bold] {ctx.config.name}")
        console.print(f"  kill-switch : {'[red]ENGAGED[/red]' if s['kill_switch'] else 'off'}")
        console.print(f"  halted      : {'[red]YES[/red] — '+s['reason'] if s['halted'] else 'no'}")
        console.print(f"  dry-run     : {'on' if s['dry_run'] else 'off'}")
        console.print(f"  audit       : {ctx.audit.count()} entries; chain "
                      + ("[green]intact[/green]" if ctx.audit.verify()[0] else "[red]BROKEN[/red]"))
        u = ctx.usage.snapshot()
        console.print(f"  usage       : daily {u['daily_pct']:.0%} / rolling {u['rolling_pct']:.0%} "
                      f"(halt at {u['halt_threshold']:.0%})")
        if s["breakers"]:
            t = Table(title="Circuit breakers")
            for c in ("target", "kind", "count", "tripped"):
                t.add_column(c)
            for b in s["breakers"]:
                t.add_row(b["target"], b["kind"], str(b["count"]),
                          "[red]TRIPPED[/red]" if b["tripped"] else "-")
            console.print(t)
        pend = ctx.approvals.pending()
        console.print(f"  approvals   : {len(pend)} pending")
        ctx.close()

    @app.command()
    def kill(config: Path = typer.Argument(...), db: Path = DB,
             reason: str = typer.Option("operator kill-switch", "--reason")) -> None:
        """Engage the global kill-switch — instantly halt all activity."""
        ctx = _ctx(config, db)
        ctx.supervisor.kill(reason)
        console.print("[red]KILL-SWITCH ENGAGED.[/red] All actions for this program will be refused.")
        ctx.close()

    @app.command()
    def resume(config: Path = typer.Argument(...), db: Path = DB) -> None:
        """Clear the kill-switch, halt, and circuit breakers."""
        ctx = _ctx(config, db)
        ctx.supervisor.clear_kill()
        ctx.supervisor.clear_halt()
        console.print("[green]Cleared.[/green] Activity may resume.")
        ctx.close()

    @app.command("dry-run")
    def dry_run(config: Path = typer.Argument(...), db: Path = DB,
                on: bool = typer.Option(True, "--on/--off")) -> None:
        """Plan-and-log intended actions without executing them."""
        ctx = _ctx(config, db)
        ctx.supervisor.set_dry_run(on)
        console.print(f"dry-run is now [bold]{'ON' if on else 'OFF'}[/bold].")
        ctx.close()

    @app.command()
    def approvals(config: Path = typer.Argument(...), db: Path = DB,
                  approve: int = typer.Option(0, "--approve"),
                  deny: int = typer.Option(0, "--deny")) -> None:
        """List the approval queue, or approve/deny a queued action."""
        ctx = _ctx(config, db)
        if approve:
            ctx.approvals.approve(approve, by="cli")
            console.print(f"[green]Approved #{approve}.[/green]")
        if deny:
            ctx.approvals.deny(deny, by="cli")
            console.print(f"[yellow]Denied #{deny}.[/yellow]")
        rows = ctx.datastore.get_approvals(ctx.program_id)
        t = Table(title="Approval queue")
        for c in ("ID", "Status", "Kind", "Target", "Impact", "Summary"):
            t.add_column(c)
        for r in rows[:30]:
            t.add_row(str(r["id"]), r["status"], r["kind"], (r["target"] or "")[:30],
                      r["impact"] or "", (r["summary"] or "")[:30])
        console.print(t)
        ctx.close()

    @app.command("audit-verify")
    def audit_verify(config: Path = typer.Argument(...), db: Path = DB) -> None:
        """Verify the append-only audit chain is intact (tamper-evident)."""
        ctx = _ctx(config, db)
        ok, bad = ctx.audit.verify()
        if ok:
            console.print(f"[green]Audit chain INTACT[/green] — {ctx.audit.count()} entries verified.")
        else:
            console.print(f"[red]AUDIT TAMPER DETECTED[/red] at entry #{bad}.")
        ctx.close()
        raise typer.Exit(0 if ok else 2)

    @app.command()
    def retention(config: Path = typer.Argument(...), db: Path = DB,
                  days: int = typer.Option(30, "--days")) -> None:
        """Purge sensitive captured data older than N days (data governance)."""
        ctx = _ctx(config, db)
        from core.governance import RetentionPolicy
        deleted = RetentionPolicy(days).purge(ctx.datastore)
        console.print(f"Retention purge (>{days}d): {deleted}")
        ctx.close()
