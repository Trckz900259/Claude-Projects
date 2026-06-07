"""
logging_setup.py — structured, reproducible logging.

Two outputs, on purpose:

  1. A friendly, colourful console stream (via Rich) so you can watch a run.
  2. A machine-readable JSON-lines file under data/logs/ so EVERY action is
     recorded for reproducibility (a core requirement: you must be able to prove
     exactly what the platform did, and when).

Call configure_logging() once at startup, then get_logger(__name__) anywhere.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from rich.logging import RichHandler

    _HAVE_RICH = True
except Exception:  # pragma: no cover - rich should be installed, but degrade ok
    _HAVE_RICH = False


class JsonLinesFormatter(logging.Formatter):
    """Render each log record as a single JSON object (one per line)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach any structured extras the caller passed via `extra={"extra_fields": {...}}`.
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


_CONFIGURED = False


def configure_logging(
    log_dir: str | Path = "data/logs",
    level: int = logging.INFO,
    run_id: str | None = None,
) -> Path:
    """
    Set up console + JSON-file logging. Idempotent (safe to call more than once).

    Returns the path of the JSON log file so callers can show/reference it.
    """
    global _CONFIGURED

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"run-{run_id}.jsonl" if run_id else f"session-{stamp}.jsonl"
    log_file = log_dir / name

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid stacking duplicate handlers if called twice.
    if _CONFIGURED:
        return log_file

    # --- Console handler (human-friendly) ---
    if _HAVE_RICH:
        console_handler: logging.Handler = RichHandler(
            rich_tracebacks=True, show_path=False, markup=False
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s | %(message)s")
        )
    console_handler.setLevel(level)
    root.addHandler(console_handler)

    # --- File handler (machine-readable JSON lines) ---
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(JsonLinesFormatter())
    file_handler.setLevel(logging.DEBUG)  # capture everything to disk
    root.addHandler(file_handler)

    _CONFIGURED = True
    logging.getLogger(__name__).info("Logging started. Audit trail: %s", log_file)
    return log_file


def get_logger(name: str) -> logging.Logger:
    """Return a module logger. Use get_logger(__name__) in each file."""
    return logging.getLogger(name)


def log_action(logger: logging.Logger, message: str, **fields) -> None:
    """
    Log an INFO line that also carries structured fields into the JSON file.

    Example:
        log_action(log, "http_request", method="GET", url=url, status=200)
    """
    logger.info(message, extra={"extra_fields": fields})
