"""
bypass.py — 403 / access-control bypass sub-module.

For any endpoint returning 401/403, we systematically try the well-known bypass
families and record which (if any) actually works (returns 2xx):

  * path normalisation  — case variation, trailing/leading/double slashes, the
    Nginx `/..;/` trick, dot and URL/Unicode-encoding variants.
  * header injection    — X-Original-URL, X-Rewrite-URL, X-Forwarded-For:127.0.0.1,
    X-Custom-IP-Authorization:127.0.0.1, X-Forwarded-Host, X-Originating-IP, ...
  * method change       — GET -> POST/PUT/HEAD/OPTIONS/TRACE.
  * API version downgrade — /v2 -> /v1, /v3 -> /v2 (older versions still live).

External tools `nomore403` and `ffuf` are wrapped when installed; otherwise the
built-in permutations run through the scope-guarded HTTP engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

from core.http_engine import HttpEngine

_IP_HEADERS = ["X-Forwarded-For", "X-Custom-IP-Authorization", "X-Originating-IP",
               "X-Remote-IP", "X-Client-IP", "X-Real-IP", "True-Client-IP"]


@dataclass
class BypassResult:
    technique: str
    detail: str          # the variant URL/header used
    status: int
    bypassed: bool
    body_excerpt: str = ""


def _swap_first_segment_case(path: str) -> str:
    parts = path.split("/")
    for i, p in enumerate(parts):
        if p:
            parts[i] = p.capitalize() if p.islower() else p.lower()
            break
    return "/".join(parts)


def path_variants(url: str) -> list[tuple[str, str]]:
    """Return (technique, variant_url) path-normalisation permutations."""
    p = urlparse(url)
    path = p.path or "/"
    out: list[tuple[str, str]] = []

    def mk(newpath, tech):
        out.append((tech, urlunparse(p._replace(path=newpath))))

    mk(_swap_first_segment_case(path), "case-variation")
    mk(path + "/", "trailing-slash")
    mk(path + "/.", "trailing-dot-slash")
    mk("/" + path.lstrip("/"), "leading-slash")          # noop-ish but cheap
    mk(path.replace("/", "//", 1), "double-slash")
    # Nginx /..;/ trick: insert before the last segment.
    if path.count("/") >= 2:
        head, _, tail = path.rpartition("/")
        mk(f"{head}/..;/{tail}", "nginx-dotdot-semicolon")
    mk(path + "%20", "trailing-encoded-space")
    mk(path + "%09", "trailing-tab")
    mk(path + "..%2f", "encoded-traversal")
    # encode the first letter of the last segment
    head, _, tail = path.rpartition("/")
    if tail:
        enc = f"%{ord(tail[0]):02x}" + tail[1:]
        mk(f"{head}/{enc}", "url-encoded-char")
    return out


def header_variants(url: str) -> list[tuple[str, dict]]:
    """Return (technique, headers) header-injection permutations."""
    p = urlparse(url)
    out: list[tuple[str, dict]] = [
        ("X-Original-URL", {"X-Original-URL": p.path}),
        ("X-Rewrite-URL", {"X-Rewrite-URL": p.path}),
        ("X-Forwarded-Host", {"X-Forwarded-Host": "localhost"}),
    ]
    for h in _IP_HEADERS:
        out.append((h, {h: "127.0.0.1"}))
    return out


def version_downgrade_variants(url: str) -> list[tuple[str, str]]:
    p = urlparse(url)
    out = []
    for hi, lo in (("/v3/", "/v2/"), ("/v2/", "/v1/"), ("/v3/", "/v1/")):
        if hi in p.path:
            out.append(("api-version-downgrade", urlunparse(p._replace(path=p.path.replace(hi, lo, 1)))))
    return out


class BypassTester:
    def __init__(self, http: HttpEngine, logger: logging.Logger | None = None) -> None:
        self.http = http
        self.log = logger or logging.getLogger("ac.bypass")

    def test(self, url: str, methods=("POST", "PUT", "HEAD", "OPTIONS")) -> list[BypassResult]:
        results: list[BypassResult] = []

        # path variants (GET)
        for tech, variant in path_variants(url) + version_downgrade_variants(url):
            res = self.http.get(variant)
            ok = 200 <= res.status_code < 300
            results.append(BypassResult(tech, variant, res.status_code, ok, (res.text or "")[:120]))

        # header variants (against the original url)
        for tech, headers in header_variants(url):
            res = self.http.get(url, headers=headers)
            ok = 200 <= res.status_code < 300
            results.append(BypassResult(f"header:{tech}", str(headers), res.status_code, ok, (res.text or "")[:120]))

        # method changes
        for m in methods:
            res = self.http.request(m, url)
            ok = 200 <= res.status_code < 300
            results.append(BypassResult(f"method:{m}", f"{m} {url}", res.status_code, ok, (res.text or "")[:120]))

        wins = [r for r in results if r.bypassed]
        if wins:
            self.log.info("403 bypass on %s via: %s", url, ", ".join(r.technique for r in wins))
        return results
