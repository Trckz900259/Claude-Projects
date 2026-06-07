"""
oob.py — out-of-band (OOB) interaction engine (shared infrastructure upgrade).

SSRF is usually BLIND: the server makes a request you can't see in the response.
You prove it by making the target call a server YOU control and watching the
"callback" arrive. This engine, an upgrade of the blind-XSS interactsh infra,
provides that with three crucial properties:

  * UNIQUE per-test token — every injected payload carries its own id, so a late
    callback maps back to the EXACT injection point and bypass used.
  * MULTI-PROTOCOL — DNS, HTTP, and raw TCP/UDP, because egress firewalls often
    block outbound HTTP but allow DNS or other ports (interactsh provides these).
  * SOURCE DISCRIMINATION — every interaction's source IP and User-Agent is
    classified as the TARGET's infrastructure vs a known third-party link scanner
    (Slack/Teams/Outlook/etc.). Only target-originated callbacks count as
    confirmed SSRF; scanner unfurls are flagged as false positives.

Two backends implement the same interface:
  * LocalHttpCollaborator — a built-in HTTP listener for SELF-HOSTED labs (the
    lab app fetches http://<you>:<port>/<token>). Deterministic, no internet.
  * InteractshCollaborator — wraps interactsh-client for REAL targets (public
    DNS/HTTP/TCP OOB).
"""

from __future__ import annotations

import json
import logging
import secrets
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Known third-party link scanners (User-Agent substrings). A callback from one of
# these is NOT proof of SSRF — it just means the URL was unfurled somewhere.
_SCANNER_UAS = {
    "Slack": ["Slackbot", "Slack-ImgProxy"],
    "Twitter/X": ["Twitterbot"],
    "Facebook": ["facebookexternalhit"],
    "Telegram": ["TelegramBot"],
    "Discord": ["Discordbot"],
    "WhatsApp": ["WhatsApp"],
    "LinkedIn": ["LinkedInBot"],
    "Microsoft/Outlook SafeLinks": ["SafeLinks", "MSOffice", "Outlook", "Microsoft Office"],
    "Google": ["Googlebot", "Feedfetcher-Google", "Google-"],
    "Bing": ["bingbot", "BingPreview"],
    "Security vendor": ["urlscan", "Qualys", "Detectify", "Cloudflare", "Censys"],
}


@dataclass
class Interaction:
    protocol: str            # dns | http | tcp | udp
    correlation_id: str      # the unique token we injected
    source_ip: str = ""
    user_agent: str = ""
    host_header: str = ""
    method: str = ""
    raw: str = ""
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_class: str = "unknown"   # target | third_party_scanner | unknown
    source_detail: str = ""


def classify_source(source_ip: str, user_agent: str,
                    target_ips: set[str] | None = None) -> tuple[str, str]:
    """Classify a callback's origin (the false-positive discriminator)."""
    if target_ips and source_ip in target_ips:
        return "target", "source IP matches the target's infrastructure"
    ua = user_agent or ""
    for name, sigs in _SCANNER_UAS.items():
        if any(s.lower() in ua.lower() for s in sigs):
            return "third_party_scanner", f"matches {name} link scanner (NOT proof of SSRF)"
    return "unknown", "unrecognised source — confirm whether it is the target before reporting"


class Collaborator(ABC):
    """Common interface for an OOB callback backend."""

    def new_token(self) -> str:
        return "ssrf" + secrets.token_hex(5)

    @abstractmethod
    def start(self) -> bool: ...

    @abstractmethod
    def payload_url(self, token: str, scheme: str = "http", path: str = "/") -> str: ...

    @abstractmethod
    def payload_host(self, token: str) -> str:
        """host[:port] form, for non-HTTP schemes (gopher://, dict://, dns)."""

    @abstractmethod
    def poll(self) -> list[Interaction]:
        """Return interactions seen since the last poll."""

    def interactions_for(self, token: str) -> list[Interaction]:
        return [i for i in self._all() if i.correlation_id == token]

    @abstractmethod
    def _all(self) -> list[Interaction]: ...

    def stop(self) -> None:
        ...


# ---------------------------------------------------------------------------
# Local HTTP collaborator (for self-hosted labs / deterministic tests)
# ---------------------------------------------------------------------------
class _CollabHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _record(self):
        token = self.path.lstrip("/").split("/")[0].split("?")[0]
        ip = self.client_address[0] if self.client_address else ""
        ua = self.headers.get("User-Agent", "")
        host = self.headers.get("Host", "")
        cls, detail = classify_source(ip, ua, self.server.target_ips)  # type: ignore[attr-defined]
        inter = Interaction(
            protocol="http", correlation_id=token, source_ip=ip, user_agent=ua,
            host_header=host, method=self.command,
            raw=f"{self.command} {self.path}\nHost: {host}\nUser-Agent: {ua}",
            source_class=cls, source_detail=detail,
        )
        self.server.record(inter)  # type: ignore[attr-defined]
        body = b'{"ok":true,"oob":"recorded"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_HEAD = _record


class _CollabServer(ThreadingHTTPServer):
    def __init__(self, addr, target_ips):
        super().__init__(addr, _CollabHandler)
        self._interactions: list[Interaction] = []
        self._lock = threading.Lock()
        self._polled = 0
        self.target_ips = target_ips or set()

    def record(self, inter: Interaction):
        with self._lock:
            self._interactions.append(inter)

    def all(self) -> list[Interaction]:
        with self._lock:
            return list(self._interactions)

    def poll(self) -> list[Interaction]:
        with self._lock:
            new = self._interactions[self._polled:]
            self._polled = len(self._interactions)
            return new


class LocalHttpCollaborator(Collaborator):
    """An HTTP listener you control — for localhost SSRF labs."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 advertise_host: str | None = None,
                 target_ips: set[str] | None = None,
                 logger: logging.Logger | None = None) -> None:
        self.host = host
        self.port = port
        self.advertise_host = advertise_host or host
        self.target_ips = target_ips or set()
        self.log = logger or logging.getLogger("oob.local")
        self._server: _CollabServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        self._server = _CollabServer((self.host, self.port), self.target_ips)
        self.port = self._server.server_address[1]  # resolve ephemeral port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.log.info("Local OOB collaborator on http://%s:%d", self.advertise_host, self.port)
        return True

    @property
    def base(self) -> str:
        return f"{self.advertise_host}:{self.port}"

    def payload_url(self, token: str, scheme: str = "http", path: str = "/") -> str:
        return f"{scheme}://{self.base}/{token}{path if path != '/' else ''}"

    def payload_host(self, token: str) -> str:
        # token is carried in the path for HTTP; for raw schemes we still hand back
        # host:port (the local collaborator can't see the token without a path).
        return self.base

    def poll(self) -> list[Interaction]:
        return self._server.poll() if self._server else []

    def _all(self) -> list[Interaction]:
        return self._server.all() if self._server else []

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# interactsh collaborator (for REAL targets — public DNS/HTTP/TCP OOB)
# ---------------------------------------------------------------------------
class InteractshCollaborator(Collaborator):
    """
    Wraps `interactsh-client`. Hands out unique-subdomain payloads
    (<token>.<registered-domain>) and parses DNS/HTTP/TCP interactions, applying
    source discrimination to each.
    """

    import re as _re
    _DOMAIN_RE = _re.compile(r"([a-z0-9]+\.[a-z0-9.\-]*oast\.[a-z]+)", _re.IGNORECASE)

    def __init__(self, server: str = "oast.fun", target_ips: set[str] | None = None,
                 logger: logging.Logger | None = None) -> None:
        self.server = server.replace("https://", "").replace("http://", "")
        self.target_ips = target_ips or set()
        self.log = logger or logging.getLogger("oob.interactsh")
        self.domain = ""
        self._proc = None
        self._interactions: list[Interaction] = []
        self._polled = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self, wait: float = 8.0) -> bool:
        import shutil
        import subprocess
        if not shutil.which("interactsh-client"):
            self.log.warning("interactsh-client missing — OOB over the internet disabled")
            return False
        try:
            self._proc = subprocess.Popen(
                ["interactsh-client", "-json", "-server", self.server],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception as exc:
            self.log.warning("could not start interactsh-client: %s", exc)
            return False
        threading.Thread(target=self._reader, daemon=True).start()
        deadline = time.time() + wait
        while time.time() < deadline and not self.domain:
            time.sleep(0.2)
        return bool(self.domain) or True

    def _reader(self):
        for line in self._proc.stdout:  # type: ignore[union-attr]
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                if not self.domain:
                    m = self._DOMAIN_RE.search(line)
                    if m:
                        self.domain = m.group(1).lower()
                continue
            self._ingest(obj)

    def _ingest(self, obj: dict):
        full_id = str(obj.get("full-id") or obj.get("unique-id") or "")
        token = ""
        m = self._re.search(r"(ssrf[0-9a-f]{10})", full_id)
        if m:
            token = m.group(1)
        ip = str(obj.get("remote-address", ""))
        raw = str(obj.get("raw-request") or obj.get("raw-response") or json.dumps(obj))
        ua = ""
        um = self._re.search(r"User-Agent:\s*(.+)", raw)
        if um:
            ua = um.group(1).strip()
        cls, detail = classify_source(ip, ua, self.target_ips)
        with self._lock:
            self._interactions.append(Interaction(
                protocol=str(obj.get("protocol", "")).lower(), correlation_id=token or full_id,
                source_ip=ip, user_agent=ua, raw=raw[:8000],
                source_class=cls, source_detail=detail))

    def payload_url(self, token: str, scheme: str = "http", path: str = "/") -> str:
        return f"{scheme}://{token}.{self.domain}{path}"

    def payload_host(self, token: str) -> str:
        return f"{token}.{self.domain}"

    def poll(self) -> list[Interaction]:
        with self._lock:
            new = self._interactions[self._polled:]
            self._polled = len(self._interactions)
            return new

    def _all(self) -> list[Interaction]:
        with self._lock:
            return list(self._interactions)

    def stop(self) -> None:
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
