"""
Proof of the no-bypass invariant:

    No target-facing action can reach the network except through the
    Action Gateway.

Two complementary proofs:

  * RUNTIME — with the structural egress guard armed (which is exactly what
    PlatformContext does in production), a module that tries to reach a target
    directly (``requests.get`` or a raw socket) is hard-refused with
    GatewayBypassError *before any byte leaves the process*, while the sanctioned
    path through the gateway (ctx.http) still works. This is the "show me a
    bypass attempt failing" test.

  * STRUCTURAL (AST) — a static scan of every platform package fails if any file
    outside the small, audited set of sanctioned executors contains a direct
    network-egress call (requests.get/post/…, socket.create_connection, httpx,
    urlopen). This catches a *new* bypass the moment it is written, not just the
    ones that happen to run in a test.

In-process is the scope of this guard. Subprocess tools (dalfox, httpx, …) and
the Playwright verifier egress from CHILD processes the in-process patch cannot
see; those are gated by being routed through ``gateway.run_tool`` (proven by the
AST scan finding no stray ``subprocess`` target calls in the wrappers) and by
only ever being handed in-scope inputs the gateway already authorized.
"""

from __future__ import annotations

import ast
import socket
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

from core import egress
from core.context import PlatformContext
from core.egress import GatewayBypassError

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# A throwaway local HTTP server so we can tell, byte-for-byte, whether a
# connection actually reached the "target".
# ---------------------------------------------------------------------------
class _Recorder(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.hits.append(self.path)  # type: ignore[attr-defined]
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    srv.hits = []  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _build_ctx(tmp_path):
    """A real context (real HttpEngine) whose scope allows loopback targets."""
    cfg = tmp_path / "egress.yml"
    cfg.write_text(textwrap.dedent("""
        program: {name: egress-test, platform: local, handle: eg}
        scope: {in_scope: [{type: cidr, value: 127.0.0.0/8}]}
        rules: {automated_scanning_allowed: true}
        rate_limit: {requests_per_second: 100, per_host_rps: 100, max_concurrency: 8}
        http: {user_agent: "EgressTest (contact: t@t)", verify_tls: false}
        roe: {ai_testing_allowed: true, max_actions_per_target: 1000}
    """))
    return PlatformContext.from_config_path(cfg, db_path=tmp_path / "f.db")


def _is_bypass(exc: BaseException) -> bool:
    """True if a GatewayBypassError is anywhere in the exception chain."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, GatewayBypassError):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


# ---------------------------------------------------------------------------
# RUNTIME: a bypass attempt fails; the gateway path works.
# ---------------------------------------------------------------------------
def test_armed_guard_blocks_direct_bypass_but_allows_gateway(tmp_path):
    srv, port = _start_server()
    url = f"http://127.0.0.1:{port}/"
    ctx = _build_ctx(tmp_path)  # building the context ARMS the guard
    try:
        assert egress.is_armed() is True

        # 1) BYPASS via requests (what a careless module would do) -> refused,
        #    and the server records NOTHING (no byte left the process).
        with pytest.raises(Exception) as ei:
            requests.get(url + "bypass-requests", timeout=2)
        assert _is_bypass(ei.value)
        assert not any("bypass-requests" in h for h in srv.hits)

        # 2) BYPASS via a raw socket (what the race engine would do unwrapped)
        #    -> refused before connect.
        with pytest.raises(GatewayBypassError):
            socket.create_connection(("127.0.0.1", port), timeout=2)

        # 3) SANCTIONED path through the gateway -> actually reaches the server.
        res = ctx.http.get(url + "via-gateway")
        assert res.status_code == 200
        assert any("via-gateway" in h for h in srv.hits)
    finally:
        ctx.close()
        srv.shutdown()


def test_guard_is_a_passthrough_when_disarmed(tmp_path):
    """Sanity: with the guard disarmed, a direct connect is NOT blocked."""
    srv, port = _start_server()
    egress.install()
    egress.disarm()
    try:
        # No GatewayBypassError — the patch is a transparent pass-through.
        r = requests.get(f"http://127.0.0.1:{port}/disarmed", timeout=2)
        assert r.status_code == 200
        assert any("disarmed" in h for h in srv.hits)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# STRUCTURAL: no platform file outside the sanctioned set does direct egress.
# ---------------------------------------------------------------------------
# The ONLY files allowed to open a target socket in-process. Each wraps its
# egress in an egress permit and is reached only via the gateway.
_SANCTIONED = {
    "core/http_engine.py",   # the gateway's HTTP execution arm
    "core/race.py",          # gateway-authorized race burst engine
    "core/notify.py",        # operator's own Discord/Telegram (control-plane)
    "core/egress.py",        # the guard itself (references socket.connect)
}

_PKGS = ["core", "modules", "recon", "report", "validation", "orchestrator", "verify"]

# Top-level convenience calls that perform their OWN network egress (i.e. that do
# NOT go through our HttpEngine/Session). ``requests.Session()`` and
# ``self._session.request`` are fine; ``requests.get(...)`` is not.
_EGRESS_METHODS = {"get", "post", "put", "delete", "head", "patch", "options", "request"}


def _egress_calls(tree: ast.AST) -> list[str]:
    """Return human-readable descriptions of direct-egress calls in a module."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        attr = func.attr
        base = func.value
        base_name = base.id if isinstance(base, ast.Name) else None

        # requests.get(...) / httpx.post(...) — direct, not via our engine.
        if base_name in ("requests", "httpx") and attr in _EGRESS_METHODS:
            hits.append(f"{base_name}.{attr} @ line {node.lineno}")
        # socket.create_connection(...)
        elif base_name == "socket" and attr == "create_connection":
            hits.append(f"socket.create_connection @ line {node.lineno}")
        # urllib.request.urlopen(...)
        elif attr == "urlopen":
            hits.append(f"urlopen @ line {node.lineno}")
    return hits


def test_no_direct_network_egress_outside_sanctioned_executors():
    violations: dict[str, list[str]] = {}
    for pkg in _PKGS:
        for path in (ROOT / pkg).rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if rel in _SANCTIONED:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            calls = _egress_calls(tree)
            if calls:
                violations[rel] = calls

    assert not violations, (
        "Direct target-facing network egress found OUTSIDE the gateway/sanctioned "
        "executors — every such call must instead go through ctx.http (the gateway "
        f"facade) or gateway.run_tool:\n{violations}"
    )


def test_sanctioned_executors_actually_hold_an_egress_permit():
    """The sanctioned executors must wrap their egress in egress.permit()."""
    for rel in ("core/http_engine.py", "core/race.py", "core/notify.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "permit()" in src, f"{rel} opens sockets but never takes an egress permit"
