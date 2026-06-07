"""
sourcing.py — where endpoints come from (three feeds).

The access-control engines need a catalogue of endpoints to test. We source them
from three places and normalise everything into the `endpoints` table:

  1. RECON INVENTORY  — the URLs Prompt 1's recon already harvested.
  2. SPEC INGESTION   — OpenAPI/Swagger files and Postman collections you provide
                        (they tell us methods, params, and expected responses).
  3. AUTO-OPENAPI     — when no spec is published, we synthesise one from the
                        traffic you captured (templating ids in paths).

`templatize_path` collapses concrete ids (/api/users/1) into templates
(/api/users/{id}) so the same endpoint isn't catalogued once per id.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

import yaml

from core.context import PlatformContext
from core.scope import host_of

_NUM = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,}$")

log = logging.getLogger("ac.sourcing")


def templatize_path(path: str) -> str:
    """/api/users/1/orders/42 -> /api/users/{id}/orders/{id} (uuids -> {uuid})."""
    out = []
    for seg in path.split("/"):
        if _NUM.match(seg):
            out.append("{id}")
        elif _UUID.match(seg):
            out.append("{uuid}")
        elif _LONG_TOKEN.match(seg) and not seg.isalpha():
            out.append("{token}")
        else:
            out.append(seg)
    return "/".join(out)


# ---------------------------------------------------------------------------
# Feed 1: recon inventory
# ---------------------------------------------------------------------------
def ingest_recon_inventory(ctx: PlatformContext) -> int:
    ds, pid = ctx.datastore, ctx.program_id
    n = 0
    for row in ds.get_urls(pid):
        url = row["url"]
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        ds.add_endpoint(pid, method="GET", path_template=templatize_path(p.path),
                        base_url=base, source="recon")
        n += 1
    log.info("recon feed: %d endpoint(s)", n)
    return n


# ---------------------------------------------------------------------------
# Feed 2: OpenAPI / Swagger + Postman ingestion
# ---------------------------------------------------------------------------
def _load_structured(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def ingest_openapi(ctx: PlatformContext, path: str) -> int:
    spec = _load_structured(path)
    ds, pid = ctx.datastore, ctx.program_id
    servers = spec.get("servers", [])
    base = servers[0]["url"] if servers else ""
    # Swagger 2.0 fallback
    if not base and spec.get("host"):
        scheme = (spec.get("schemes") or ["https"])[0]
        base = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"

    n = 0
    for path_tmpl, methods in (spec.get("paths") or {}).items():
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            params = []
            for param in op.get("parameters", []) if isinstance(op, dict) else []:
                params.append({
                    "name": param.get("name"), "location": param.get("in"),
                    "required": param.get("required", False),
                })
            ds.add_endpoint(pid, method=method.upper(), path_template=path_tmpl,
                            base_url=base, params=params, source="openapi",
                            meta={"summary": op.get("summary", "") if isinstance(op, dict) else ""})
            n += 1
    log.info("openapi feed: %d endpoint(s) from %s", n, path)
    return n


def ingest_postman(ctx: PlatformContext, path: str) -> int:
    coll = _load_structured(path)
    ds, pid = ctx.datastore, ctx.program_id
    n = 0

    def walk(items):
        nonlocal n
        for it in items:
            if "item" in it:           # a folder
                walk(it["item"])
                continue
            req = it.get("request")
            if not req:
                continue
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            raw = url.get("raw") if isinstance(url, dict) else url
            if not raw:
                continue
            p = urlparse(raw.replace("{{baseUrl}}", "").strip())
            base = f"{p.scheme}://{p.netloc}" if p.scheme else ""
            ds.add_endpoint(pid, method=method, path_template=templatize_path(p.path or raw),
                            base_url=base, source="postman",
                            meta={"name": it.get("name", "")})
            n += 1

    walk(coll.get("item", []))
    log.info("postman feed: %d endpoint(s) from %s", n, path)
    return n


# ---------------------------------------------------------------------------
# Feed 3: auto-OpenAPI from captured traffic
# ---------------------------------------------------------------------------
def auto_openapi_from_traffic(ctx: PlatformContext) -> dict:
    """Synthesise endpoints (and a minimal OpenAPI doc) from captured traffic."""
    ds, pid = ctx.datastore, ctx.program_id
    paths: dict[str, dict] = {}
    n = 0
    for row in ds.get_captured(pid):
        p = urlparse(row["url"])
        tmpl = templatize_path(p.path)
        base = f"{p.scheme}://{p.netloc}"
        method = (row["method"] or "GET").upper()
        ds.add_endpoint(pid, method=method, path_template=tmpl, base_url=base,
                        source="traffic",
                        meta={"observed_status": row["status_code"]})
        paths.setdefault(tmpl, {})[method.lower()] = {
            "responses": {str(row["status_code"] or 200): {"description": "observed"}}
        }
        n += 1
    log.info("traffic feed: %d endpoint(s) synthesised", n)
    return {"openapi": "3.0.0", "info": {"title": f"{ctx.config.name} (auto)", "version": "0"},
            "paths": paths}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def discover_endpoints(
    ctx: PlatformContext, openapi: str | None = None, postman: str | None = None,
    use_recon: bool = True, use_traffic: bool = True,
) -> dict:
    counts = {"recon": 0, "openapi": 0, "postman": 0, "traffic": 0}
    if use_recon:
        counts["recon"] = ingest_recon_inventory(ctx)
    if openapi:
        counts["openapi"] = ingest_openapi(ctx, openapi)
    if postman:
        counts["postman"] = ingest_postman(ctx, postman)
    if use_traffic:
        spec = auto_openapi_from_traffic(ctx)
        counts["traffic"] = sum(len(m) for m in spec["paths"].values())
    return counts
