"""
capture.py — get real authenticated traffic into the datastore.

Two ways:

  1. LIVE proxy (mitmproxy): `launch_mitm_capture()` runs mitmdump with our addon.
     You set your browser's proxy to it and browse as each test account. Best for
     thorough capture, but requires installing mitmproxy's CA cert in your browser.

  2. HAR import: `import_har()` reads a .har file you exported from your browser's
     DevTools (Network tab → "Save all as HAR"). Zero setup — great for beginners.

Both are scope-filtered: only in-scope requests are stored.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from core.config import ProgramConfig
from core.datastore import Datastore
from core.scope import ScopeEnforcer, host_of

log = logging.getLogger("capture")


def launch_mitm_capture(config_path: str, db_path: str, port: int, capture_as: str = "") -> int:
    """Run mitmdump with our capture addon. Blocks until you stop it (Ctrl-C)."""
    addon = Path(__file__).resolve().parent / "mitm_addon.py"
    env = os.environ.copy()
    env["BBP_CONFIG"] = str(config_path)
    env["BBP_DB"] = str(db_path)
    env["BBP_CAPTURE_AS"] = capture_as
    # Ensure the addon can import our packages.
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent) + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-m", "mitmproxy.tools.dump", "-s", str(addon), "--listen-port", str(port)]
    return subprocess.run(cmd, env=env).returncode


def import_har(
    config: ProgramConfig, datastore: Datastore, program_id: int,
    har_path: str, capture_as: str = "",
) -> int:
    """Import a browser-exported .har file. Returns the count of stored requests."""
    scope: ScopeEnforcer = config.scope
    data = json.loads(Path(har_path).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    stored = 0
    for e in entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        url = req.get("url", "")
        if not url or not scope.check(url).allowed:
            continue  # scope-filter even imported traffic
        req_headers = {h["name"]: h["value"] for h in req.get("headers", [])}
        resp_headers = {h["name"]: h["value"] for h in resp.get("headers", [])}
        req_body = (req.get("postData", {}) or {}).get("text", "")
        resp_body = (resp.get("content", {}) or {}).get("text", "")
        datastore.add_captured(
            program_id, method=req.get("method", "GET"), url=url, host=host_of(url),
            req_headers=req_headers, req_body=req_body or "",
            status_code=resp.get("status"), resp_headers=resp_headers,
            resp_body=resp_body or "", captured_as=capture_as, source="har",
        )
        stored += 1
    log.info("Imported %d in-scope request(s) from %s", stored, har_path)
    return stored
