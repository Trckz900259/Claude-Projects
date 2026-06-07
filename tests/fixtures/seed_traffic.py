"""
seed_traffic.py — dev helper: simulate captured browsing into the datastore.

In real use you'd capture traffic with `bbp capture` (mitmproxy) or `bbp
import-traffic --har`. For local validation against the bundled vulnerable_api,
this replays a realistic authenticated browsing sequence under each of your
identities and stores the request/response pairs as captured_traffic — exactly
what the replay+compare engine consumes.

Usage:  python tests/fixtures/seed_traffic.py config/local-api.yml
"""

from __future__ import annotations

import sys

from core.context import PlatformContext

BASE = "http://127.0.0.1:8100"

# (identity, method, path, json_body)
PLAN = [
    ("userA", "GET", "/api/me", None),
    ("userA", "GET", "/api/users/1", None),
    ("userA", "GET", "/api/users/1/orders", None),
    ("userB", "GET", "/api/me", None),
    ("userB", "GET", "/api/users/2", None),
    ("userB", "GET", "/api/users/2/orders", None),
    ("userA", "POST", "/api/profile", '{"name": "Alice2"}'),
    ("userB", "GET", "/admin/stats", None),
]


def main():
    config = sys.argv[1] if len(sys.argv) > 1 else "config/local-api.yml"
    ctx = PlatformContext.from_config_path(config)
    sm = ctx.session_manager()
    sm.prime()
    n = 0
    for ident, method, path, body in PLAN:
        url = BASE + path
        headers = {"Content-Type": "application/json"} if body else None
        res = sm.request_as(ident, method, url, data=body, headers=headers)
        ctx.datastore.add_captured(
            ctx.program_id, method=method, url=url, host="127.0.0.1",
            req_headers=res.request_headers, req_body=body or "",
            status_code=res.status_code, resp_headers=res.response_headers,
            resp_body=res.text, captured_as=ident, source="seed",
        )
        n += 1
    print(f"seeded {n} captured request(s) into {config}")
    ctx.close()


if __name__ == "__main__":
    main()
