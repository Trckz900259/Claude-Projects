"""
http_engine.py — the ONLY sanctioned way to make an outbound request.

Every single request the platform sends goes through HttpEngine.request(), and
that method enforces, in order:

  1. SCOPE       — ask the ScopeEnforcer; if the target is not on the allow-list,
                   raise OutOfScopeError immediately. No network call happens.
  2. RATE LIMIT  — wait for a polite slot (global + per-host + concurrency).
  3. USER-AGENT  — stamp our identifiable researcher User-Agent on the request.

Because recon and every vuln module are required to use this engine (and never
`requests`/`httpx` directly), the scope allow-list literally cannot be bypassed.

It also captures the full raw request and response text, which the reporting
stage needs to produce reproducible, consultancy-grade write-ups.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import requests

from core.config import HttpConfig
from core.egress import permit
from core.exceptions import OutOfScopeError
from core.logging_setup import log_action
from core.ratelimit import RateLimiter
from core.scope import ScopeEnforcer, host_of


@dataclass
class HttpResult:
    """Everything about one request/response, ready for findings & reports."""

    url: str
    method: str
    status_code: int
    request_headers: dict[str, str]
    request_body: str
    response_headers: dict[str, str]
    text: str
    elapsed_ms: float
    final_url: str  # after any redirects
    error: str | None = None
    raw_response: requests.Response | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.error is None and 0 < self.status_code < 600

    def request_as_text(self) -> str:
        """A copy-pasteable raw HTTP request block for the report."""
        lines = [f"{self.method} {self.url} HTTP/1.1"]
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body)
        return "\n".join(lines)

    def response_as_text(self, max_body: int = 20000) -> str:
        """A raw HTTP response block (body truncated) for the report."""
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.response_headers.items():
            lines.append(f"{k}: {v}")
        body = self.text or ""
        if len(body) > max_body:
            body = body[:max_body] + f"\n...[truncated {len(self.text) - max_body} bytes]"
        lines.append("")
        lines.append(body)
        return "\n".join(lines)


class HttpEngine:
    """Scope-guarded, rate-limited, identifiable HTTP client."""

    def __init__(
        self,
        scope: ScopeEnforcer,
        rate_limiter: RateLimiter,
        http_config: HttpConfig,
        logger: logging.Logger | None = None,
    ) -> None:
        self.scope = scope
        self.rate_limiter = rate_limiter
        self.config = http_config
        self.log = logger or logging.getLogger(__name__)
        self._session = requests.Session()
        # COOKIE-STATELESS: reject all cookies so a Set-Cookie from one request
        # can never auto-attach to a later one. This is essential for multi-
        # identity testing — each request must carry ONLY its identity's explicit
        # auth, with zero implicit state leaking between identities.
        from http.cookiejar import DefaultCookiePolicy

        self._session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        # A simple counter so logs/reports can reference request numbers.
        self._counter = 0

    # -- the one method everything funnels through ------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data=None,
        json=None,
        timeout: float | None = None,
    ) -> HttpResult:
        method = method.upper()

        # ---------- 1) SCOPE: hard refusal, before anything else ----------
        decision = self.scope.check(url)
        if not decision.allowed:
            log_action(
                self.log,
                "scope_refused",
                method=method,
                url=url,
                reason=decision.reason,
            )
            # This is the non-negotiable safety boundary.
            raise OutOfScopeError(url, decision.reason)

        host = host_of(url)

        # ---------- 2) RATE LIMIT: wait for a polite slot ----------
        with self.rate_limiter.slot(host):
            # ---------- 3) USER-AGENT: always identify ourselves ----------
            send_headers = {"User-Agent": self.config.user_agent}
            if headers:
                send_headers.update(headers)

            self._counter += 1
            start = time.monotonic()
            try:
                # SANCTIONED EGRESS: this is the gateway's HTTP execution arm, so
                # we hold an egress permit while the socket is opened. Any OTHER
                # in-process attempt to reach the network (without this permit)
                # is hard-refused by the egress guard (core/egress.py).
                with permit():
                    resp = self._session.request(
                        method=method,
                        url=url,
                        headers=send_headers,
                        params=params,
                        data=data,
                        json=json,
                        timeout=timeout or self.config.timeout_seconds,
                        allow_redirects=self.config.follow_redirects,
                        verify=self.config.verify_tls,
                    )
            except requests.RequestException as exc:
                elapsed = (time.monotonic() - start) * 1000
                log_action(
                    self.log,
                    "http_error",
                    n=self._counter,
                    method=method,
                    url=url,
                    error=str(exc),
                    elapsed_ms=round(elapsed, 1),
                )
                # We return a result with an error rather than raising, so the
                # fault-tolerant orchestrator can record it and move on.
                return HttpResult(
                    url=url,
                    method=method,
                    status_code=0,
                    request_headers=send_headers,
                    request_body=_body_to_text(data, json),
                    response_headers={},
                    text="",
                    elapsed_ms=round(elapsed, 1),
                    final_url=url,
                    error=str(exc),
                )

            elapsed = (time.monotonic() - start) * 1000

        # Build the request body text from what requests actually sent.
        req_body = ""
        if resp.request.body is not None:
            req_body = (
                resp.request.body
                if isinstance(resp.request.body, str)
                else resp.request.body.decode("utf-8", "replace")
            )

        result = HttpResult(
            url=url,
            method=method,
            status_code=resp.status_code,
            request_headers=dict(resp.request.headers),
            request_body=req_body,
            response_headers=dict(resp.headers),
            text=resp.text,
            elapsed_ms=round(elapsed, 1),
            final_url=resp.url,
            raw_response=resp,
        )

        log_action(
            self.log,
            "http_request",
            n=self._counter,
            method=method,
            url=url,
            status=resp.status_code,
            bytes=len(resp.content or b""),
            elapsed_ms=result.elapsed_ms,
        )
        return result

    # -- thin convenience wrappers ----------------------------------------
    def get(self, url: str, **kw) -> HttpResult:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> HttpResult:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw) -> HttpResult:
        return self.request("HEAD", url, **kw)

    def close(self) -> None:
        self._session.close()


def _body_to_text(data, json) -> str:
    """Best-effort string form of a request body, for error-path results."""
    if data is None and json is None:
        return ""
    if isinstance(data, (str, bytes)):
        return data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    import json as _json

    try:
        return _json.dumps(json if json is not None else data)
    except Exception:
        return str(json if json is not None else data)
