"""
seeds.py — populate a target's inventory before the benchmark runs a module.

In real use you'd `bbp recon` / `bbp capture`. For the benchmark we seed
deterministically so the measurement is stable. Each function mirrors the
discovery a real run would produce for that target kind.
"""

from __future__ import annotations

import json

from core.context import PlatformContext
from recon.pipeline import ReconPipeline


def seed_recon(ctx: PlatformContext, base_url: str) -> None:
    """Crawl a target (katana) to populate URLs/params — used for XSS."""
    ReconPipeline(ctx).run(seed_urls=[base_url], do_subfinder=False, do_gau=False,
                           do_httpx=False, do_arjun=False, crawl_depth=2)


def seed_accesscontrol(ctx: PlatformContext, base_url: str) -> None:
    """Replay an authenticated browsing sequence under each identity + extras."""
    sm = ctx.session_manager()
    sm.prime()
    plan = [
        ("userA", "GET", "/api/me", None), ("userA", "GET", "/api/users/1", None),
        ("userA", "GET", "/api/users/1/orders", None),
        ("userB", "GET", "/api/me", None), ("userB", "GET", "/api/users/2", None),
        ("userB", "GET", "/api/users/2/orders", None),
        ("userA", "POST", "/api/profile", '{"name": "Alice2"}'),
        ("userB", "GET", "/admin/stats", None), ("userB", "GET", "/admin/secret", None),
    ]
    for ident, method, path, body in plan:
        url = base_url + path
        headers = {"Content-Type": "application/json"} if body else None
        res = sm.request_as(ident, method, url, data=body, headers=headers)
        ctx.datastore.add_captured(ctx.program_id, method=method, url=url, host="127.0.0.1",
                                   req_headers=res.request_headers, req_body=body or "",
                                   status_code=res.status_code, resp_headers=res.response_headers,
                                   resp_body=res.text, captured_as=ident, source="benchmark")
    # synthetic single-use coupon redeem (kept fresh for the race test)
    ctx.datastore.add_captured(ctx.program_id, method="POST", url=base_url + "/api/redeem",
                               host="127.0.0.1", req_headers={"Content-Type": "application/json"},
                               req_body='{"code": "WELCOME50"}', status_code=200,
                               resp_headers={}, resp_body='{"redeemed":"WELCOME50"}', source="benchmark")
    # Mirror the real discover->scan workflow: populate endpoints + id params so the
    # object-level (IDOR/BOLA) engine has candidates.
    from modules.accesscontrol.idparams import IdParamIdentifier
    from modules.accesscontrol.sourcing import discover_endpoints
    discover_endpoints(ctx, use_recon=False, use_traffic=True)
    IdParamIdentifier(ctx).run()


def seed_ssrf(ctx: PlatformContext, base_url: str) -> None:
    """Register the SSRF lab's endpoints as captured traffic."""
    eps = [("GET", f"{base_url}/fetch?url=http://example.com", ""),
           ("GET", f"{base_url}/fetch-safe?url=http://example.com", ""),
           ("POST", f"{base_url}/webhook", '{"url": "http://example.com"}')]
    for method, url, body in eps:
        ctx.datastore.add_captured(ctx.program_id, method=method, url=url, host="127.0.0.1",
                                   req_headers={"Content-Type": "application/json"} if body else {},
                                   req_body=body, status_code=200, resp_headers={},
                                   resp_body="", source="benchmark")


SEEDERS = {"recon": seed_recon, "accesscontrol": seed_accesscontrol, "ssrf": seed_ssrf}
