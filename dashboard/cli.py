"""
dashboard/cli.py — registers the `bbp dashboard` command.

It launches the Streamlit app as a subprocess, passing the datastore path through
an environment variable the app reads.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console

console = Console()


def register(app: typer.Typer) -> None:
    @app.command()
    def dashboard(
        db: Path = typer.Option(Path("data/findings.db"), help="SQLite datastore path."),
        port: int = typer.Option(8501, help="Port to serve the dashboard on."),
        headless: bool = typer.Option(False, "--headless", help="Don't auto-open a browser."),
    ) -> None:
        """Launch the Streamlit dashboard to explore programs, findings, and callbacks."""
        app_path = Path(__file__).resolve().parent / "app.py"
        env = os.environ.copy()
        env["BBP_DB_PATH"] = str(db)

        cmd = [
            sys.executable, "-m", "streamlit", "run", str(app_path),
            "--server.port", str(port),
            "--server.headless", "true" if headless else "false",
            "--browser.gatherUsageStats", "false",
        ]
        console.print(f"[green]Starting dashboard[/green] at http://localhost:{port}  (Ctrl-C to stop)")
        try:
            subprocess.run(cmd, env=env)
        except KeyboardInterrupt:
            console.print("\nDashboard stopped.")
        except FileNotFoundError:
            console.print("[red]Streamlit not found. Install it: pip install streamlit[/red]")
            raise typer.Exit(code=1)
