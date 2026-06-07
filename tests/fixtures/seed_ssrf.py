"""
seed_ssrf.py — dev helper: register the SSRF lab's endpoints as captured traffic.

(In real use you'd `bbp recon` / `bbp capture` / `bbp import-traffic`.) This makes
validation deterministic against tests/fixtures/vulnerable_ssrf.py.

Usage:  python tests/fixtures/seed_ssrf.py config/local-ssrf.yml [base_url]
"""

from __future__ import annotations

import sys

from core.context import PlatformContext

BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8300"

ENDPOINTS = [
    ("GET", f"{BASE}/fetch?url=http://example.com", ""),
    ("GET", f"{BASE}/fetch-safe?url=http://example.com", ""),
    ("POST", f"{BASE}/webhook", '{"url": "http://example.com"}'),
]


def main():
    config = sys.argv[1] if len(sys.argv) > 1 else "config/local-ssrf.yml"
    ctx = PlatformContext.from_config_path(config)
    for method, url, body in ENDPOINTS:
        ctx.datastore.add_captured(
            ctx.program_id, method=method, url=url, host="127.0.0.1",
            req_headers={"Content-Type": "application/json"} if body else {},
            req_body=body, status_code=200, resp_headers={}, resp_body="", source="seed")
    print(f"seeded {len(ENDPOINTS)} SSRF endpoints into {config}")
    ctx.close()


if __name__ == "__main__":
    main()
