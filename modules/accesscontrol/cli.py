"""
modules/accesscontrol/cli.py — foundation commands for the access-control module.

  bbp identities <config>            show configured identities (>= 2 required)
  bbp capture <config> [--as NAME]   live mitmproxy capture of your browsing
  bbp import-traffic <config> --har  import a browser-exported .har file
  bbp harvest-tokens <config>        find auth tokens in captured traffic

(The scan itself runs via `bbp scan <config> --module accesscontrol`.)
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from core.capture import import_har, launch_mitm_capture
from core.context import PlatformContext
from core.exceptions import BBPlatformError
from core.identity import load_identities
from core.tokens import harvest_traffic, suggest_identity_auth

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def identities(
        config: Path = typer.Argument(..., help="Program profile."),
        db: Path = typer.Option(Path("data/findings.db")),
    ) -> None:
        """Load and display the identity profiles (and check the >=2 rule)."""
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        try:
            sm = ctx.session_manager()
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            ctx.close()
            raise typer.Exit(1)

        # Prime re-login flows so the table shows the real (redacted) auth.
        sm.prime()

        table = Table(title=f"Identities — {ctx.config.name}")
        for col in ("Name", "Role", "Auth", "Owned IDs", "Relogin"):
            table.add_column(col)
        for p in sm.profiles.values():
            table.add_row(p.name, p.role or "-", p.auth_summary(),
                          ", ".join(p.owned_ids) or "-", "yes" if p.relogin else "no")
        console.print(table)

        n_auth = len(sm.authenticated())
        if n_auth < 2:
            console.print(f"[yellow]⚠ Only {n_auth} authenticated identity(ies). "
                          f"Access-control testing needs >= 2 of YOUR OWN accounts.[/yellow]")
        else:
            console.print(f"[green]✓ {n_auth} authenticated identities — ready.[/green]")
        ctx.close()

    @app.command()
    def capture(
        config: Path = typer.Argument(..., help="Program profile."),
        port: int = typer.Option(8080, help="Proxy listen port."),
        as_identity: str = typer.Option("", "--as", help="Identity you're browsing as."),
        db: Path = typer.Option(Path("data/findings.db")),
    ) -> None:
        """
        Start a mitmproxy capture. Point your browser's proxy at it and browse the
        in-scope target as your account; in-scope traffic is stored. Ctrl-C to stop.
        """
        console.print(f"[green]Starting mitmproxy capture on port {port}[/green] "
                      f"(identity: {as_identity or 'unspecified'}).")
        console.print("Set your browser HTTP/HTTPS proxy to "
                      f"127.0.0.1:{port} and install mitmproxy's CA cert (http://mitm.it). "
                      "Ctrl-C to stop.")
        launch_mitm_capture(str(config), str(db), port, capture_as=as_identity)

    @app.command("import-traffic")
    def import_traffic(
        config: Path = typer.Argument(..., help="Program profile."),
        har: Path = typer.Option(..., "--har", help="Path to a .har export from DevTools."),
        as_identity: str = typer.Option("", "--as", help="Identity this traffic belongs to."),
        db: Path = typer.Option(Path("data/findings.db")),
    ) -> None:
        """Import a browser-exported HAR file (no proxy setup needed)."""
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        try:
            n = import_har(ctx.config, ctx.datastore, ctx.program_id, str(har), capture_as=as_identity)
            console.print(f"[green]Imported {n} in-scope request(s)[/green] from {har}.")
        finally:
            ctx.close()

    @app.command("harvest-tokens")
    def harvest_tokens(
        config: Path = typer.Argument(..., help="Program profile."),
        db: Path = typer.Option(Path("data/findings.db")),
    ) -> None:
        """Find auth tokens in captured traffic and suggest an identity auth block."""
        try:
            ctx = PlatformContext.from_config_path(config, db_path=db)
        except BBPlatformError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)
        rows = ctx.datastore.get_captured(ctx.program_id)
        tokens = harvest_traffic(rows)
        if not tokens:
            console.print("[yellow]No tokens found. Capture/import some traffic first.[/yellow]")
            ctx.close()
            return
        table = Table(title=f"Harvested tokens ({len(tokens)})")
        for col in ("Type", "Location", "Preview", "alg/decoded"):
            table.add_column(col)
        for t in tokens:
            extra = t.meta.get("alg") or t.meta.get("decoded", "")
            table.add_row(t.type, t.location, t.preview(), str(extra))
        console.print(table)
        console.print("\n[bold]Suggested identity `auth:` block[/bold] (paste into your identities file):")
        import yaml as _yaml
        console.print(_yaml.safe_dump({"auth": suggest_identity_auth(tokens)}, sort_keys=False))
        ctx.close()
