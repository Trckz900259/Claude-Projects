"""
race.py — concurrency / race-condition request engine (shared HTTP addition).

Race conditions (TOCTOU, limit-overrun) need many requests to arrive at the
server within the same tiny processing window. Normal rate-limited sending is the
opposite of what's needed, so this engine deliberately bursts a SMALL, bounded
number of requests as simultaneously as possible, two ways:

  1. HTTP/2 SINGLE-PACKET attack (preferred): open one H2 connection, send each
     request's headers/body but WITHHOLD the frame that completes it, then flush
     all the completing (END_STREAM) frames in a single TCP packet. All requests
     then complete server-side almost simultaneously. (James Kettle's technique.)

  2. HTTP/1 LAST-BYTE synchronisation (fallback): open N connections, send each
     request except its final byte, then release the final byte on all of them
     back-to-back.

Safety: every target is scope-checked first (out-of-scope = refused), the
identifiable User-Agent is sent, and the burst size is bounded. The CALLER is
responsible for the rules gate (automated scanning allowed) and for using only
your OWN fresh accounts/codes (rule #4).
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.exceptions import OutOfScopeError
from core.scope import ScopeEnforcer, host_of


@dataclass
class RaceResponse:
    status: int
    body_len: int
    elapsed_ms: float
    error: str = ""


@dataclass
class RaceResult:
    mode: str
    url: str
    count: int
    responses: list[RaceResponse] = field(default_factory=list)

    @property
    def status_distribution(self) -> dict[int, int]:
        dist: dict[int, int] = {}
        for r in self.responses:
            dist[r.status] = dist.get(r.status, 0) + 1
        return dist

    @property
    def successes(self) -> int:
        """How many requests returned a 2xx — the key signal for limit-overrun."""
        return sum(1 for r in self.responses if 200 <= r.status < 300)


class RaceEngine:
    def __init__(
        self,
        scope: ScopeEnforcer,
        user_agent: str,
        verify_tls: bool = True,
        logger: logging.Logger | None = None,
        timeout: float = 12.0,
    ) -> None:
        self.scope = scope
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.log = logger or logging.getLogger("race")
        self.timeout = timeout

    # -- public: pick the best mode, fall back gracefully -----------------
    def race(
        self, url: str, method: str = "POST", headers: dict | None = None,
        body: str = "", count: int = 20,
    ) -> RaceResult:
        decision = self.scope.check(url)
        if not decision.allowed:
            raise OutOfScopeError(url, decision.reason)
        count = max(2, min(count, 50))  # bounded burst

        if urlparse(url).scheme == "https":
            try:
                return self._http2_single_packet(url, method, headers or {}, body, count)
            except Exception as exc:
                self.log.info("HTTP/2 single-packet unavailable (%s); using HTTP/1 last-byte", exc)
        return self._http1_last_byte(url, method, headers or {}, body, count)

    # -- HTTP/2 single-packet ---------------------------------------------
    def _http2_single_packet(
        self, url: str, method: str, headers: dict, body: str, count: int
    ) -> RaceResult:
        import h2.connection
        import h2.events

        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or 443
        path = p.path or "/"
        if p.query:
            path += "?" + p.query

        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        raw = socket.create_connection((host, port), timeout=self.timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock = ctx.wrap_socket(raw, server_hostname=host)
        if sock.selected_alpn_protocol() != "h2":
            sock.close()
            raise RuntimeError("server did not negotiate HTTP/2")

        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        body_bytes = body.encode() if body else b""
        hdrs = [
            (":method", method.upper()),
            (":authority", host),
            (":scheme", "https"),
            (":path", path),
            ("user-agent", self.user_agent),
        ]
        for k, v in headers.items():
            if k.lower() not in (":method", ":authority", ":scheme", ":path", "host"):
                hdrs.append((k.lower(), v))
        if body_bytes:
            hdrs.append(("content-length", str(len(body_bytes))))

        stream_ids = []
        # 1) Send everything EXCEPT the frame that ends each stream.
        for i in range(count):
            sid = conn.get_next_available_stream_id()
            stream_ids.append(sid)
            conn.send_headers(sid, hdrs, end_stream=False)
            if body_bytes:
                # send the body but NOT the final 1 byte (that 1 byte ends it)
                conn.send_data(sid, body_bytes[:-1] or b"", end_stream=False)
        sock.sendall(conn.data_to_send())
        time.sleep(0.10)  # let the server buffer all the preambles

        # 2) Build all the completing frames, then flush in ONE write (one packet).
        for sid in stream_ids:
            if body_bytes:
                conn.send_data(sid, body_bytes[-1:], end_stream=True)
            else:
                conn.send_data(sid, b"", end_stream=True)
        start = time.monotonic()
        sock.sendall(conn.data_to_send())  # <-- the single packet

        result = RaceResult(mode="http2-single-packet", url=url, count=count)
        status_by_stream: dict[int, int] = {}
        len_by_stream: dict[int, int] = {}
        open_streams = set(stream_ids)
        sock.settimeout(self.timeout)
        try:
            while open_streams:
                data = sock.recv(65535)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        for k, v in event.headers:
                            if k == b":status":
                                status_by_stream[event.stream_id] = int(v)
                    elif isinstance(event, h2.events.DataReceived):
                        len_by_stream[event.stream_id] = len_by_stream.get(event.stream_id, 0) + len(event.data)
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        open_streams.discard(event.stream_id)
                outbound = conn.data_to_send()
                if outbound:
                    sock.sendall(outbound)
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        elapsed = (time.monotonic() - start) * 1000
        for sid in stream_ids:
            result.responses.append(RaceResponse(
                status=status_by_stream.get(sid, 0),
                body_len=len_by_stream.get(sid, 0),
                elapsed_ms=round(elapsed, 1),
            ))
        try:
            sock.close()
        except Exception:
            pass
        self.log.info("race(h2) %s x%d -> %s", url, count, result.status_distribution)
        return result

    # -- HTTP/1 last-byte synchronisation ---------------------------------
    def _http1_last_byte(
        self, url: str, method: str, headers: dict, body: str, count: int
    ) -> RaceResult:
        p = urlparse(url)
        https = p.scheme == "https"
        host = p.hostname or ""
        port = p.port or (443 if https else 80)
        path = (p.path or "/") + (("?" + p.query) if p.query else "")
        body_bytes = body.encode() if body else b""

        lines = [f"{method.upper()} {path} HTTP/1.1", f"Host: {host}",
                 f"User-Agent: {self.user_agent}", "Connection: close"]
        for k, v in headers.items():
            if k.lower() not in ("host", "user-agent", "connection", "content-length"):
                lines.append(f"{k}: {v}")
        if body_bytes:
            lines.append(f"Content-Length: {len(body_bytes)}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode() + body_bytes
        head, last = request[:-1], request[-1:]

        ctx = ssl.create_default_context() if https else None
        if ctx and not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        socks = []
        for _ in range(count):
            try:
                s = socket.create_connection((host, port), timeout=self.timeout)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if https:
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.sendall(head)  # everything but the last byte
                socks.append(s)
            except Exception as exc:
                self.log.debug("race conn setup failed: %s", exc)

        time.sleep(0.10)  # ensure all heads are sent
        start = time.monotonic()
        for s in socks:  # release the final byte on all, back-to-back
            try:
                s.send(last)
            except Exception:
                pass

        result = RaceResult(mode="http1-last-byte", url=url, count=len(socks))
        for s in socks:
            try:
                s.settimeout(self.timeout)
                data = b""
                while True:
                    chunk = s.recv(65535)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 200000:
                        break
                status = _parse_http1_status(data)
                result.responses.append(RaceResponse(
                    status=status, body_len=len(data),
                    elapsed_ms=round((time.monotonic() - start) * 1000, 1),
                ))
            except Exception as exc:
                result.responses.append(RaceResponse(0, 0, 0, error=str(exc)))
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        self.log.info("race(h1) %s x%d -> %s", url, len(socks), result.status_distribution)
        return result


def _parse_http1_status(data: bytes) -> int:
    try:
        first = data.split(b"\r\n", 1)[0]  # b"HTTP/1.1 200 OK"
        return int(first.split(b" ")[1])
    except Exception:
        return 0
