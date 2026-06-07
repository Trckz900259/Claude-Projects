"""
reflection.py — does our input come back in the response, and how raw?

Step one of reflected-XSS hunting: inject a unique marker into a parameter and
see whether it appears in the response. We tack a small sentinel of special
characters onto the marker so we can also tell which of < > " ' survived
UN-encoded — a strong hint that a breakout is possible. The authoritative proof
still comes later from the headless-browser verifier; this just narrows things.

All requests go through the shared HttpEngine, so scope + rate-limit + UA apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_engine import HttpEngine, HttpResult

# Special characters whose survival hints a breakout is possible.
SENTINEL = "'\"<>"


def inject_param(url: str, param: str, value: str) -> str:
    """Return `url` with the query parameter `param` set to `value`."""
    parts = urlparse(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    # doseq=True expands our single-item lists correctly.
    new_query = urlencode(query, doseq=True)
    return urlunparse(parts._replace(query=new_query))


@dataclass
class ReflectionProbe:
    reflected: bool
    test_url: str
    response_body: str = ""
    survived: set[str] = field(default_factory=set)
    http_result: HttpResult | None = None


def probe_reflection(http: HttpEngine, url: str, param: str, marker: str) -> ReflectionProbe:
    """Inject `marker`+sentinel into `param`, fetch, and analyse the reflection."""
    test_value = marker + SENTINEL
    test_url = inject_param(url, param, test_value)
    res = http.get(test_url)
    body = res.text or ""

    reflected = marker in body
    survived: set[str] = set()
    if reflected:
        i = body.find(marker)
        trailing = body[i + len(marker): i + len(marker) + 12]
        for ch in SENTINEL:
            if ch in trailing:
                survived.add(ch)

    return ReflectionProbe(
        reflected=reflected,
        test_url=test_url,
        response_body=body,
        survived=survived,
        http_result=res,
    )
