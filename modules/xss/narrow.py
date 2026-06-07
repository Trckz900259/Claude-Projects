"""
narrow.py — use `gf` xss patterns to PRIORITISE which URLs to test first.

The spec calls for gf + kxss to narrow harvested URLs to likely XSS candidates.
We use `gf xss` for this because it is PURE PATTERN MATCHING over URL strings —
it sends no network traffic, so it can't violate our rate-limit/User-Agent
guarantees. It just flags URLs whose parameter names/shapes are commonly XSS-prone.

We deliberately do NOT auto-run `kxss` here: kxss makes its OWN HTTP requests
without honouring our rate limiter or User-Agent, which would break the safety
model. Its job — detecting which parameters reflect unfiltered characters — is
already done, more safely, by our own scope-guarded reflection prober
(modules/xss/reflection.py). `kxss` remains installed for manual use.
"""

from __future__ import annotations

import logging
import subprocess

from core.tooling import is_available


def gf_xss_priority_urls(urls: list[str], logger: logging.Logger | None = None) -> set[str]:
    """Return the subset of `urls` that `gf xss` considers XSS-likely (no network)."""
    log = logger or logging.getLogger("xss.narrow")
    if not urls or not is_available("gf"):
        return set()
    try:
        proc = subprocess.run(
            ["gf", "xss"], input="\n".join(sorted(set(urls))),
            capture_output=True, text=True, timeout=30,
        )
        flagged = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
        if flagged:
            log.info("gf xss flagged %d/%d URLs as higher-priority", len(flagged), len(urls))
        return flagged
    except Exception as exc:  # pragma: no cover - defensive
        log.debug("gf narrowing skipped: %s", exc)
        return set()
