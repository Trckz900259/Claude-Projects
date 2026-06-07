"""
browser_fetch.py — full-browser fetch primitive (shared, reuses Playwright).

Some SSRF proofs need a request with a custom method and headers that a simple
client can't easily express through proxies/redirects — e.g. AWS IMDSv2 (a PUT to
get a token, then a GET carrying X-aws-ec2-metadata-token), or header-routing
SSRF. This primitive uses Playwright's request engine to issue arbitrary
method/header requests with browser-grade behaviour.

It is SCOPE-GUARDED: because it bypasses the normal HttpEngine, it re-checks the
program scope before every request (out-of-scope = refused).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from core.scope import ScopeEnforcer


@dataclass
class FetchResult:
    status: int
    headers: dict
    body: str
    error: str = ""


class BrowserFetcher:
    def __init__(self, scope: ScopeEnforcer, user_agent: str,
                 verify_tls: bool = True, logger: logging.Logger | None = None) -> None:
        self.scope = scope
        self.user_agent = user_agent
        self.verify_tls = verify_tls
        self.log = logger or logging.getLogger("verify.browser")

    def available(self) -> bool:
        try:
            import playwright.sync_api  # noqa: F401
            return True
        except Exception:
            return False

    def fetch(self, url: str, method: str = "GET", headers: dict | None = None,
              data: str | None = None) -> FetchResult:
        decision = self.scope.check(url)
        if not decision.allowed:
            return FetchResult(0, {}, "", error=f"refused (out of scope): {decision.reason}")
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return FetchResult(0, {}, "", error="Playwright not installed")
        try:
            with sync_playwright() as p:
                ctx = p.request.new_context(
                    extra_http_headers={"User-Agent": self.user_agent, **(headers or {})},
                    ignore_https_errors=not self.verify_tls)
                resp = ctx.fetch(url, method=method, data=data, timeout=12000)
                body = resp.text()
                result = FetchResult(resp.status, dict(resp.headers), body[:20000])
                ctx.dispose()
                return result
        except Exception as exc:
            return FetchResult(0, {}, "", error=f"browser fetch error: {exc}")
