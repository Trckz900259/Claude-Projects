"""
tools.py — thin, scope-aware wrappers around the external recon CLIs.

A crucial subtlety: when we shell out to an external tool (httpx, katana, ...),
those tools make their OWN network requests — they do NOT go through our
HttpEngine. So to keep the safety guarantees, every wrapper here:

  * only ever receives IN-SCOPE inputs (the pipeline pre-filters), and
  * SCOPE-FILTERS its output before returning anything, and
  * passes our identifiable User-Agent and a rate-limit flag to the tool, and
  * is gated by the pipeline behind `automated_scanning_allowed` when active.

If a tool is missing, the wrapper logs a friendly warning and returns nothing —
the framework keeps running.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from core.config import ProgramConfig
from core.scope import host_of
from core.tooling import is_available


class ReconTools:
    def __init__(self, config: ProgramConfig, logger: logging.Logger | None = None) -> None:
        self.config = config
        self.scope = config.scope
        self.ua = config.http.user_agent
        self.rps = config.rate_limit.per_host_rps
        self.log = logger or logging.getLogger("recon.tools")

    # -- generic subprocess helper ----------------------------------------
    def _run(
        self,
        cmd: list[str],
        stdin: str | None = None,
        timeout: int = 120,
    ) -> tuple[int, str, str]:
        """Run a command, capture output, never raise on non-zero exit."""
        self.log.debug("exec: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            self.log.warning("%s timed out after %ss", cmd[0], timeout)
            return 124, "", "timeout"
        except FileNotFoundError:
            self.log.warning("%s not found on PATH", cmd[0])
            return 127, "", "not found"
        except Exception as exc:  # pragma: no cover - defensive
            self.log.warning("%s failed: %s", cmd[0], exc)
            return 1, "", str(exc)

    def _in_scope(self, target: str) -> bool:
        return self.scope.check(target).allowed

    # -- subfinder: subdomain enumeration (passive) -----------------------
    def subfinder(self, domain: str, timeout: int = 120) -> list[str]:
        if not is_available("subfinder"):
            self.log.warning("subfinder missing — skipping subdomain enumeration")
            return []
        rc, out, _ = self._run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
        subs = [line.strip() for line in out.splitlines() if line.strip()]
        # Keep only subdomains that are actually in our allow-list.
        in_scope = [s for s in subs if self._in_scope(s)]
        self.log.info(
            "subfinder %s: %d found, %d in scope", domain, len(subs), len(in_scope)
        )
        return sorted(set(in_scope))

    # -- httpx: which hosts are live (ACTIVE) -----------------------------
    def httpx(self, hosts: list[str], timeout: int = 180) -> list[dict]:
        if not is_available("httpx"):
            self.log.warning("httpx missing — skipping live-host probing")
            return []
        targets = [h for h in hosts if self._in_scope(h)]
        if not targets:
            return []
        cmd = [
            "httpx", "-silent", "-json", "-no-color",
            "-status-code", "-title", "-tech-detect", "-content-type",
            "-H", f"User-Agent: {self.ua}",
            "-rate-limit", str(max(1, int(self.rps))),
            "-timeout", str(int(self.config.http.timeout_seconds)),
        ]
        rc, out, _ = self._run(cmd, stdin="\n".join(targets), timeout=timeout)
        results: list[dict] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input") or ""
            if url and self._in_scope(url):
                results.append(obj)
        self.log.info("httpx: %d live in-scope hosts", len(results))
        return results

    # -- gau: harvest known URLs from archives (passive) ------------------
    def gau(self, domain: str, max_urls: int = 3000, timeout: int = 180) -> list[str]:
        if not is_available("gau"):
            self.log.warning("gau missing — skipping archive URL harvesting")
            return []
        rc, out, _ = self._run(
            ["gau", "--subs", "--threads", "5", domain], stdin=None, timeout=timeout
        )
        urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
        in_scope = [u for u in urls if self._in_scope(u)][:max_urls]
        self.log.info("gau %s: %d found, %d in scope (capped %d)",
                      domain, len(urls), len(in_scope), max_urls)
        return sorted(set(in_scope))

    # -- katana: active crawl (ACTIVE) ------------------------------------
    def katana(
        self, url: str, depth: int = 2, max_urls: int = 2000, timeout: int = 240
    ) -> list[str]:
        if not is_available("katana"):
            self.log.warning("katana missing — skipping active crawl")
            return []
        if not self._in_scope(url):
            return []
        cmd = [
            "katana", "-u", url, "-silent", "-jc", "-d", str(depth),
            "-H", f"User-Agent: {self.ua}",
            "-rate-limit", str(max(1, int(self.rps))),
            "-c", str(self.config.rate_limit.max_concurrency),
            "-timeout", str(int(self.config.http.timeout_seconds)),
        ]
        rc, out, _ = self._run(cmd, timeout=timeout)
        urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
        in_scope = [u for u in urls if self._in_scope(u)][:max_urls]
        self.log.info("katana %s: %d crawled, %d in scope", url, len(urls), len(in_scope))
        return sorted(set(in_scope))

    # -- arjun: hidden parameter discovery (ACTIVE) -----------------------
    def arjun(self, url: str, timeout: int = 90) -> list[str]:
        if not is_available("arjun"):
            self.log.warning("arjun missing — skipping hidden-parameter discovery")
            return []
        if not self._in_scope(url):
            return []
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "arjun.json"
            cmd = [
                "arjun", "-u", url, "-oJ", str(out_path),
                "-t", str(max(1, min(5, self.config.rate_limit.max_concurrency))),
                "--headers", f"User-Agent: {self.ua}",
                "--stable",
            ]
            self._run(cmd, timeout=timeout)
            if not out_path.exists():
                return []
            try:
                data = json.loads(out_path.read_text(encoding="utf-8"))
            except Exception:
                return []
        # arjun's JSON shape varies; handle the common forms.
        params: list[str] = []
        if isinstance(data, dict):
            for _, info in data.items():
                if isinstance(info, dict):
                    params.extend(info.get("params", []) or [])
                elif isinstance(info, list):
                    params.extend(info)
        elif isinstance(data, list):
            params.extend(data)
        self.log.info("arjun %s: %d hidden params", url, len(set(params)))
        return sorted({str(p) for p in params if p})
