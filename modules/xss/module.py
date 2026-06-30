"""
module.py — the XSS vulnerability module (the first real module).

It implements the common Module interface:

  build_candidates(): turn the shared inventory into independent units of work —
      one 'reflected' candidate per (url, parameter), and one 'dom' candidate per
      distinct page (for DOM-source→sink + CSP analysis).

  test_candidate(): for a reflected candidate — probe reflection, work out the
      context, fire context-appropriate BENIGN payloads, and confirm execution in
      a real headless browser (screenshot PoC). For a dom candidate — statically
      find source→sink flows and dynamically confirm hash-based ones, plus flag
      CSP weaknesses. Optionally fire dalfox for extra coverage and inject blind
      (OOB) payloads.

The WHOLE module is 'automated scanning' (it sends crafted requests to the
target), so setup() refuses to run unless the program profile permits it.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from core.context import PlatformContext
from core.datastore import Finding
from modules.base import Candidate, Module
from modules.xss.blind import (
    InteractshListener,
    make_blind_payloads,
    make_correlation_id,
)
from modules.xss.context import classify_reflections, ReflectionContext
from modules.xss.csp import CSPIssue
from modules.xss.dalfox import run_dalfox
from modules.xss.dom import DomAnalyzer
from modules.xss.narrow import gf_xss_priority_urls
from modules.xss.payloads import new_marker, payloads_for
from modules.xss.reflection import inject_param, probe_reflection
from report.cvss import score_for_subtype
from verify.playwright_verify import Verifier


def _severity(subtype: str) -> str:
    """Single source of truth: severity follows the CVSS v3.1 rating per subtype."""
    return score_for_subtype(subtype).rating

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class XssModule(Module):
    name = "xss"
    description = "Cross-Site Scripting: reflected, stored, DOM, and blind."

    def __init__(
        self,
        ctx: PlatformContext,
        logger: logging.Logger | None = None,
        use_dalfox: bool = True,
        use_blind: bool = True,
        max_attempts: int = 6,
        record_video: bool = False,
    ) -> None:
        super().__init__(ctx, logger)
        self.use_dalfox = use_dalfox
        self.use_blind = use_blind
        self.max_attempts = max_attempts
        self.verifier = Verifier(
            scope=ctx.config.scope,
            user_agent=ctx.config.http.user_agent,
            verify_tls=ctx.config.http.verify_tls,
            record_video=record_video,
            logger=logging.getLogger("verify"),
        )
        self.dom = DomAnalyzer(ctx.http, logger=logging.getLogger("xss.dom"))
        self.listener: InteractshListener | None = None

    # -- lifecycle --------------------------------------------------------
    def setup(self) -> None:
        # The entire module is active scanning — respect the program rule.
        self.ctx.require_automated_scanning("XSS scan")
        if not self.verifier.available():
            self.log.warning(
                "Playwright not available — candidates will be reported UNVERIFIED. "
                "Install with: pip install playwright && playwright install chromium"
            )
        # Start blind-callback listener if we can.
        if self.use_blind:
            listener = InteractshListener(
                self.ctx.config, self.ctx.datastore, self.ctx.program_id,
                logger=logging.getLogger("xss.blind"),
            )
            if listener.start():
                self.listener = listener

    def teardown(self) -> None:
        if self.listener:
            # We do NOT block waiting for late callbacks here; run
            # `bbp callbacks` separately to keep listening for hours.
            self.listener.stop()

    # -- candidate generation ---------------------------------------------
    def build_candidates(self) -> list[Candidate]:
        ds, pid = self.ctx.datastore, self.ctx.program_id
        candidates: list[Candidate] = []

        # gf flags XSS-likely URLs (pure pattern match, no network) so we test
        # the most promising parameters first — without skipping anything.
        param_rows = list(ds.get_parameters(pid))
        priority_urls = gf_xss_priority_urls([r["url"] for r in param_rows], self.log)

        # One reflected candidate per (url, parameter); priority ones come first.
        reflected: list[Candidate] = []
        seen_params: set[tuple[str, str]] = set()
        for row in param_rows:
            key = (row["url"], row["name"])
            if key in seen_params:
                continue
            seen_params.add(key)
            reflected.append(Candidate(self.name, {
                "kind": "reflected", "url": row["url"],
                "param": row["name"], "param_type": row["param_type"],
                "priority": row["url"] in priority_urls,
            }))
        reflected.sort(key=lambda c: not c.data.get("priority"))  # priority first
        candidates.extend(reflected)

        # One dom candidate per distinct page URL.
        seen_pages: set[str] = set()
        for row in ds.get_urls(pid):
            page = row["url"].split("#")[0]
            if page in seen_pages:
                continue
            seen_pages.add(page)
            candidates.append(Candidate(self.name, {"kind": "dom", "url": page}))

        self.log.info("Built %d XSS candidates", len(candidates))
        return candidates

    # -- the work ---------------------------------------------------------
    def test_candidate(self, candidate: Candidate) -> list[Finding]:
        kind = candidate.data.get("kind")
        if kind == "reflected":
            return self._test_reflected(candidate.data["url"], candidate.data["param"])
        if kind == "dom":
            return self._test_dom(candidate.data["url"])
        return []

    # ---- reflected / stored ----
    def _test_reflected(self, url: str, param: str) -> list[Finding]:
        findings: list[Finding] = []
        http = self.ctx.http
        marker = new_marker()

        probe = probe_reflection(http, url, param, marker)

        if probe.reflected:
            contexts = classify_reflections(probe.response_body, marker) or [
                ReflectionContext("html_body", "", "fallback", 0, "")
            ]
            verified = self._fire_and_verify(url, param, marker, contexts, probe)
            if verified:
                findings.append(verified)
            else:
                # Reflected but our payloads didn't visibly fire. Try dalfox's
                # larger payload set before downgrading to 'unverified'.
                dalfox_finding = self._try_dalfox(url, param) if self.use_dalfox else None
                if dalfox_finding:
                    findings.append(dalfox_finding)
                else:
                    findings.append(self._unverified_reflected(url, param, probe))

        # Blind / OOB injection (independent of whether it reflected).
        if self.use_blind and self.listener and self.listener.callback_host(""):
            findings.append(self._inject_blind(url, param, marker))

        return findings

    def _fire_and_verify(
        self, url: str, param: str, marker: str,
        contexts: list[ReflectionContext], probe,
    ) -> Finding | None:
        if not self.verifier.available():
            return None
        attempts = 0
        for ctx in contexts:
            for payload in payloads_for(ctx.context, marker, ctx.quote or '"'):
                if attempts >= self.max_attempts:
                    return None
                attempts += 1
                test_url = inject_param(url, param, payload)
                vres = self.verifier.verify_url(
                    test_url, marker, capture_name=f"{param}-{ctx.context}"
                )
                if vres.verified:
                    # Capture the server's raw response to the payload URL.
                    payload_res = self.ctx.http.get(test_url)
                    return Finding(
                        type="xss", subtype="reflected", severity=_severity("reflected"),
                        status="verified", url=url, parameter=param,
                        payload=payload, context=ctx.context,
                        request=payload_res.request_as_text(),
                        response=payload_res.response_as_text(),
                        title=f"Reflected XSS in '{param}' ({ctx.context} context)",
                        description=(
                            f"User input in parameter '{param}' is reflected into the "
                            f"{ctx.context} context without adequate output encoding, and a "
                            f"benign proof payload executed (alert carrying marker {marker})."
                        ),
                        cvss_score=None, cvss_vector="",
                        evidence={
                            "context_detail": ctx.detail,
                            "reflection_snippet": ctx.snippet,
                            "special_chars_survived": sorted(probe.survived),
                            "dialog_text": vres.dialog_text,
                            "test_url": test_url,
                            "marker": marker,
                        },
                        poc_screenshot=vres.screenshot_path,
                        poc_video=vres.video_path,
                    )
        return None

    def _try_dalfox(self, url: str, param: str) -> Finding | None:
        results = run_dalfox(self.ctx.config, url, param=param, logger=self.log,
                             gateway=getattr(self.ctx, "gateway", None))
        for r in results:
            marker = new_marker()
            # Prefer dalfox's PoC URL; verify it ourselves for a screenshot.
            if r.poc_url and self.verifier.available():
                vres = self.verifier.verify_url(r.poc_url, marker, capture_name=f"{param}-dalfox")
                verified = vres.verified
            else:
                vres = None
                verified = False
            payload_res = self.ctx.http.get(r.poc_url) if r.poc_url else None
            return Finding(
                type="xss", subtype="reflected",
                severity=_severity("reflected") if verified else "medium",
                status="verified" if verified else "new",
                url=url, parameter=param, payload=r.payload, context="dalfox",
                request=payload_res.request_as_text() if payload_res else "",
                response=payload_res.response_as_text() if payload_res else "",
                title=f"Reflected XSS in '{param}' (dalfox)",
                description=(
                    f"dalfox identified an XSS payload for parameter '{param}'. "
                    + ("Confirmed firing in a headless browser." if verified
                       else "NOT independently confirmed — verify manually before reporting.")
                ),
                evidence={
                    "dalfox_type": r.type, "dalfox_severity": r.severity,
                    "cwe": r.cwe, "evidence": r.evidence, "poc_url": r.poc_url,
                },
                poc_screenshot=vres.screenshot_path if vres else "",
            )
        return None

    def _unverified_reflected(self, url: str, param: str, probe) -> Finding:
        return Finding(
            type="xss", subtype="reflected", severity="medium", status="new",
            url=url, parameter=param, payload=probe.test_url, context="unknown",
            request=probe.http_result.request_as_text() if probe.http_result else "",
            response=probe.http_result.response_as_text() if probe.http_result else "",
            title=f"Possible reflected XSS in '{param}' (UNVERIFIED)",
            description=(
                f"Input in '{param}' is reflected in the response and these special "
                f"characters survived un-encoded: {sorted(probe.survived)}. Execution was "
                f"NOT confirmed by the browser verifier — do not report without manual proof."
            ),
            evidence={"special_chars_survived": sorted(probe.survived)},
        )

    def _inject_blind(self, url: str, param: str, marker: str) -> Finding:
        corr = make_correlation_id(url, param)
        host = self.listener.callback_host(corr)  # type: ignore[union-attr]
        payloads = make_blind_payloads(host, marker)
        for bp in payloads[:2]:  # fire a couple; keep it light
            try:
                self.ctx.http.get(inject_param(url, param, bp))
            except Exception:
                pass
        return Finding(
            type="xss", subtype="blind", severity="info", status="new",
            url=url, parameter=param, payload=payloads[0], context="blind",
            title=f"Blind XSS probe injected into '{param}' (awaiting callback)",
            description=(
                f"A benign out-of-band payload was injected into '{param}'. If it "
                f"executes later (e.g. in an admin view), our interactsh listener will "
                f"record a callback for correlation id {corr} and mark this verified."
            ),
            evidence={"correlation_id": corr, "callback_host": host, "marker": marker},
        )

    # ---- DOM + CSP ----
    def _test_dom(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        analysis = self.dom.analyze_page(url)

        for flow in analysis.flows:
            verified = False
            screenshot = ""
            test_url = ""
            # Dynamically confirm hash/query-driven flows with a benign payload.
            if self.verifier.available() and any(
                s in flow.source for s in ("hash", "search", "location", "URL")
            ):
                marker = new_marker()
                payload = f"<img src=x onerror=alert('{marker}')>"
                test_url = f"{url}#{quote(payload)}"
                vres = self.verifier.verify_url(test_url, marker, capture_name="dom")
                verified = vres.verified
                screenshot = vres.screenshot_path

            findings.append(Finding(
                type="xss", subtype="dom",
                severity=_severity("dom"),
                status="verified" if verified else "new",
                url=url, parameter=flow.source, payload=test_url, context="dom",
                title=f"DOM XSS: {flow.source} -> {flow.sink}"
                      + ("" if verified else " (static, UNVERIFIED)"),
                description=(
                    f"Client-side code flows attacker-controllable '{flow.source}' into the "
                    f"dangerous sink '{flow.sink}' in {flow.script_ref}. "
                    + ("A benign payload via the URL fragment executed in the browser."
                       if verified else
                       "This is a STATIC finding — confirm manually before reporting.")
                ),
                evidence={
                    "source": flow.source, "sink": flow.sink,
                    "code_snippet": flow.snippet, "script": flow.script_ref,
                    "test_url": test_url,
                },
                poc_screenshot=screenshot,
            ))

        # CSP weaknesses (one summary finding per page that has any).
        if analysis.csp_issues:
            findings.append(self._csp_finding(url, analysis.csp_issues))
        return findings

    def _csp_finding(self, url: str, issues: list[CSPIssue]) -> Finding:
        worst = max(issues, key=lambda i: _SEVERITY_ORDER.get(i.severity, 0))
        lines = [f"- [{i.severity}] {i.directive}: {i.issue} — {i.detail}" for i in issues]
        return Finding(
            type="xss", subtype="csp", severity=worst.severity, status="new",
            url=url, parameter="", payload="", context="header",
            title=f"Content-Security-Policy weaknesses ({len(issues)})",
            description="The page's CSP has the following weaknesses:\n" + "\n".join(lines),
            evidence={"issues": [i.__dict__ for i in issues]},
        )
