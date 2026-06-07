"""
dalfox.py — wrapper around dalfox, the dedicated XSS scanner.

dalfox has a deep, well-maintained payload set and mutation engine. We let it do
what it's great at — finding and firing reflected/stored payloads — and then we
hand its proof-of-concept URLs to OUR Playwright verifier for the authoritative,
screenshot-backed confirmation. Best of both worlds.

dalfox makes its own requests (not via our HttpEngine), so the caller MUST only
invoke this on in-scope URLs and only when automated scanning is permitted. We
still pass our User-Agent and a polite delay derived from the per-host rate.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core.config import ProgramConfig
from core.tooling import is_available


@dataclass
class DalfoxResult:
    payload: str = ""
    poc_url: str = ""
    type: str = ""
    severity: str = ""
    cwe: str = ""
    evidence: str = ""


def run_dalfox(
    config: ProgramConfig,
    url: str,
    param: str | None = None,
    timeout: int = 150,
    logger: logging.Logger | None = None,
) -> list[DalfoxResult]:
    log = logger or logging.getLogger("xss.dalfox")
    if not is_available("dalfox"):
        log.warning("dalfox missing — skipping automated firing")
        return []
    if not config.scope.check(url).allowed:
        log.warning("dalfox: refusing out-of-scope url %s", url)
        return []

    per_host_rps = config.rate_limit.per_host_rps or 1.0
    delay_ms = int(1000 / per_host_rps) if per_host_rps > 0 else 0

    with tempfile.TemporaryDirectory() as tmp:
        out_path = Path(tmp) / "dalfox.json"
        cmd = [
            "dalfox", "url", url,
            "--format", "json",
            "-o", str(out_path),
            "--no-spinner", "--silence", "--skip-bav",
            "--user-agent", config.http.user_agent,
            "--delay", str(delay_ms),
            "--worker", str(max(1, config.rate_limit.max_concurrency)),
        ]
        if config.http.timeout_seconds:
            cmd += ["--timeout", str(int(config.http.timeout_seconds))]
        if param:
            cmd += ["-p", param]

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning("dalfox timed out on %s", url)
            return []
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("dalfox failed on %s: %s", url, exc)
            return []

        raw = out_path.read_text(encoding="utf-8") if out_path.exists() else ""

    return _parse(raw)


def _parse(raw: str) -> list[DalfoxResult]:
    """dalfox JSON output may be an array or one object per line — handle both."""
    raw = (raw or "").strip()
    if not raw:
        return []
    objects: list[dict] = []
    try:
        data = json.loads(raw)
        objects = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    results: list[DalfoxResult] = []
    for o in objects:
        if not isinstance(o, dict):
            continue
        # dalfox schema: "payload" = the payload, "data" = the full PoC URL,
        # "type" R/V/G, "severity", "cwe", "evidence"/"message_str".
        data = str(o.get("data", ""))
        payload = str(o.get("payload", ""))
        if not payload and not data:
            continue  # skip dalfox's trailing empty {} object
        results.append(
            DalfoxResult(
                payload=payload,
                poc_url=data if data.startswith("http") else "",
                type=str(o.get("type", "")),
                severity=str(o.get("severity", "")),
                cwe=str(o.get("cwe", "")),
                evidence=str(o.get("evidence", o.get("message_str", ""))),
            )
        )
    return results
