"""
dom.py — static analysis for DOM-based XSS.

DOM XSS happens entirely in the browser: a 'source' of attacker-controllable
data (e.g. location.hash) flows into a dangerous 'sink' (e.g. innerHTML) without
sanitisation. The server never sees the payload, so server-side reflection
checks miss it.

We fetch a page's JavaScript (inline + same-origin external) and look for a
source and a sink close together — a likely flow. We report the exact code
snippet so it can be confirmed by hand and shown in the report. We also pull the
page's CSP and flag weaknesses (via csp.py).

This is heuristic static analysis: it flags *likely* flows to investigate, which
the verifier then tries to confirm dynamically (e.g. with a #hash payload).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.http_engine import HttpEngine
from core.scope import host_of
from modules.xss.csp import CSPIssue, analyze_csp

# Attacker-controllable sources.
SOURCES = [
    r"location\.hash", r"location\.search", r"location\.href", r"location\.pathname",
    r"document\.URL", r"document\.documentURI", r"document\.referrer",
    r"window\.name", r"document\.cookie", r"location(?![\w.])",
    r"\.searchParams", r"postMessage", r"event\.data",
]
# Dangerous sinks.
SINKS = [
    r"\.innerHTML\b", r"\.outerHTML\b", r"document\.write(?:ln)?\s*\(",
    r"\.insertAdjacentHTML\s*\(", r"\beval\s*\(", r"new\s+Function\s*\(",
    r"setTimeout\s*\(\s*[\"'`]?", r"setInterval\s*\(\s*[\"'`]?",
    r"\.html\s*\(", r"\$\s*\(", r"\.src\s*=",
]

_SOURCE_RE = re.compile("|".join(SOURCES))
_SINK_RE = re.compile("|".join(SINKS))


@dataclass
class DomFlow:
    source: str
    sink: str
    snippet: str
    script_ref: str  # 'inline #2' or the external URL


@dataclass
class DomAnalysis:
    url: str
    flows: list[DomFlow] = field(default_factory=list)
    csp_issues: list[CSPIssue] = field(default_factory=list)
    scripts_analyzed: int = 0


class DomAnalyzer:
    def __init__(self, http: HttpEngine, logger: logging.Logger | None = None) -> None:
        self.http = http
        self.log = logger or logging.getLogger("xss.dom")

    def analyze_page(self, url: str, max_external: int = 8) -> DomAnalysis:
        result = DomAnalysis(url=url)
        res = self.http.get(url)
        if not res.ok or not res.text:
            return result

        # CSP weaknesses from the response headers.
        csp_header = res.response_headers.get("Content-Security-Policy") or \
            res.response_headers.get("content-security-policy")
        result.csp_issues = analyze_csp(csp_header)

        soup = BeautifulSoup(res.text, "lxml")
        scripts: list[tuple[str, str]] = []  # (ref, code)

        # Inline scripts.
        for i, tag in enumerate(soup.find_all("script")):
            if tag.get("src"):
                continue
            code = tag.string or tag.get_text() or ""
            if code.strip():
                scripts.append((f"inline #{i}", code))

        # Same-origin external scripts (fetched through the scope-guarded engine).
        external = 0
        for tag in soup.find_all("script", src=True):
            if external >= max_external:
                break
            src = urljoin(url, tag["src"])
            if host_of(src) != host_of(url):
                continue  # only same-origin, and only if in scope
            if not self.http.scope.check(src).allowed:
                continue
            jr = self.http.get(src)
            if jr.ok and jr.text:
                scripts.append((src, jr.text))
                external += 1

        result.scripts_analyzed = len(scripts)
        for ref, code in scripts:
            result.flows.extend(self._scan(code, ref))
        return result

    def _scan(self, code: str, ref: str) -> list[DomFlow]:
        """Find sinks and check for a nearby source — a likely DOM flow."""
        flows: list[DomFlow] = []
        seen: set[tuple[str, str]] = set()
        for sink_match in _SINK_RE.finditer(code):
            # Look behind (and a little ahead) for a source feeding this sink.
            window = code[max(0, sink_match.start() - 300): sink_match.end() + 60]
            src_match = _SOURCE_RE.search(window)
            if not src_match:
                continue
            sink = sink_match.group(0).strip()
            source = src_match.group(0).strip()
            sig = (source, sink)
            if sig in seen:
                continue
            seen.add(sig)
            # The snippet = the line containing the sink, trimmed.
            line_start = code.rfind("\n", 0, sink_match.start()) + 1
            line_end = code.find("\n", sink_match.end())
            line_end = line_end if line_end != -1 else len(code)
            snippet = code[line_start:line_end].strip()[:300]
            flows.append(DomFlow(source=source, sink=sink, snippet=snippet, script_ref=ref))
        return flows
