"""
egress.py — the STRUCTURAL network-egress chokepoint.

Phase 1 gave us the Action Gateway: every module's HTTP flows through
``GatewayHttp -> ActionGateway -> HttpEngine`` and every tool through
``gateway.run_tool``. That is the *policy* chokepoint. This module adds the
*structural* guarantee that backs it up — the invariant we actually want to be
able to prove:

    No target-facing action can reach the network except through the
    Action Gateway.

How it works: once the guard is **armed**, we monkeypatch ``socket.socket.connect``
(and ``connect_ex``). A connect to a TCP/IP host is then allowed only if either

  1. a thread-local PERMIT is active — set by one of the small, audited set of
     *sanctioned executors* that wrap their own egress (see below), or
  2. the destination host is on the CONTROL-PLANE allow-list — loopback is *not*
     on it; only the operator's own out-of-band / notification infrastructure,
     explicitly registered, ever is.

Anything else — a module that does ``import requests; requests.get(target)``, a
stray ``socket.create_connection``, a new dependency that phones home — raises
:class:`GatewayBypassError` *before a single byte leaves the process*.

The sanctioned executors (the ONLY code allowed to open a target socket) are:

  * :meth:`core.http_engine.HttpEngine.request` — the gateway's HTTP arm.
  * :class:`core.race.RaceEngine` — the gateway-authorized race burst engine.
  * :func:`core.notify.send_notification` — the operator's own Discord/Telegram.

This is defence-in-depth, *not* a replacement for the gateway: the gateway still
runs the full RoE / supervisor / usage / approval pipeline before any of those
executors are reached. The egress guard just turns "forgot to go through the
gateway" from a silent hole into a hard, immediate failure.

Subprocess tools (dalfox, httpx, …) egress from CHILD processes, which this
in-process patch cannot see — those are gated structurally by being routed
through ``gateway.run_tool`` instead (and proven by the AST test).
"""

from __future__ import annotations

import socket
import threading
from contextlib import contextmanager
from urllib.parse import urlparse

from core.exceptions import BBPlatformError


class GatewayBypassError(BBPlatformError):
    """A target-facing network call tried to bypass the Action Gateway."""


# --- thread-local permit ----------------------------------------------------
# A sanctioned executor sets this for the duration of its own egress. Nested
# permits are supported with a simple depth counter so re-entrancy is safe.
_state = threading.local()


def _depth() -> int:
    return getattr(_state, "depth", 0)


def permitted() -> bool:
    """True if the current thread is inside a sanctioned executor's egress."""
    return _depth() > 0


@contextmanager
def permit():
    """
    Mark the current thread as inside a sanctioned executor's egress.

    Wrap the *actual* socket I/O of a sanctioned executor in this. While it is
    active, connects on this thread are allowed; outside it (and while armed),
    they raise :class:`GatewayBypassError`.
    """
    _state.depth = _depth() + 1
    try:
        yield
    finally:
        _state.depth = max(0, _depth() - 1)


# --- control-plane allow-list ----------------------------------------------
# Hosts that are NEVER the target: the operator's own out-of-band / notification
# infrastructure. Loopback is deliberately NOT auto-allowed — a localhost lab IS
# a target, and the bypass test relies on a localhost connect being blocked.
_allow_hosts: set[str] = set()
_lock = threading.Lock()


def allow_control_plane(*hosts: str) -> None:
    """Register operator/control-plane hosts (notify webhooks, OOB server)."""
    with _lock:
        for h in hosts:
            if not h:
                continue
            host = urlparse(h).hostname if "://" in h else h
            if host:
                _allow_hosts.add(host.lower())


def _is_control_plane(host: str) -> bool:
    with _lock:
        return (host or "").lower() in _allow_hosts


def _host_of_addr(address) -> str:
    """Pull the host out of a socket address tuple ((ip, port[, ...]))."""
    if isinstance(address, (tuple, list)) and address:
        return str(address[0])
    return str(address)


# --- the guard --------------------------------------------------------------
_armed = False
_installed = False
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex


def _check(sock: socket.socket, address) -> None:
    """Raise if this connect is a target-facing egress without a permit."""
    if not _armed or permitted():
        return
    # Only INET sockets are network egress; AF_UNIX et al. are local IPC.
    if getattr(sock, "family", None) not in (socket.AF_INET, socket.AF_INET6):
        return
    host = _host_of_addr(address)
    if _is_control_plane(host):
        return
    raise GatewayBypassError(
        f"BLOCKED in-process connect to {host!r}: a target-facing network call "
        f"must go through the Action Gateway (no egress permit is active on this "
        f"thread). See core/egress.py — only the sanctioned HTTP/race/notify "
        f"executors may open a socket."
    )


def _guarded_connect(self, address, *args, **kwargs):
    _check(self, address)
    return _orig_connect(self, address, *args, **kwargs)


def _guarded_connect_ex(self, address, *args, **kwargs):
    _check(self, address)
    return _orig_connect_ex(self, address, *args, **kwargs)


def install() -> None:
    """Monkeypatch socket.connect with the guard (idempotent, no-op if armed off)."""
    global _installed
    if _installed:
        return
    socket.socket.connect = _guarded_connect          # type: ignore[assignment]
    socket.socket.connect_ex = _guarded_connect_ex     # type: ignore[assignment]
    _installed = True


def arm() -> None:
    """Begin enforcing the no-bypass invariant (installs the patch if needed)."""
    global _armed
    install()
    _armed = True


def disarm() -> None:
    """Stop enforcing (the patch stays installed but becomes a pass-through)."""
    global _armed
    _armed = False


def is_armed() -> bool:
    return _armed
