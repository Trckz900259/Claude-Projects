"""
pipeline.py — the reconnaissance pipeline.

It runs ONCE and fills the shared inventory in the datastore:

    seeds (from scope) ─▶ subfinder ─▶ host pool
                                         │
                                         ├─▶ httpx   (which are live?)        [active]
                                         ├─▶ gau     (known URLs, archives)   [passive]
                                         └─▶ katana  (crawl live hosts)       [active]
                                                       │
    harvested URLs ─▶ extract query params [passive]   │
    sample of URLs ─▶ arjun (hidden params)            [active]

Passive steps (subfinder, gau, query-param extraction) query third-party data
or parse what we already have — they never send traffic to the target, so they
always run. ACTIVE steps (httpx, katana, arjun) hit the target's own servers, so
they are gated behind the program's `automated_scanning_allowed` rule.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qsl, urlparse

from core.context import PlatformContext
from core.scope import host_of
from recon.tools import ReconTools


def derive_seeds(ctx: PlatformContext) -> tuple[list[str], list[str]]:
    """
    Work out what to seed recon with, purely from the in-scope rules:
      * domain/wildcard rules  -> domain seeds (for subfinder & gau)
      * url rules              -> host seeds (and the URL itself)
    Returns (domain_seeds, host_seeds).
    """
    domain_seeds: set[str] = set()
    host_seeds: set[str] = set()
    for rule in ctx.config.scope.in_scope:
        if rule.type == "domain":
            domain_seeds.add(rule.value.lower())
            host_seeds.add(rule.value.lower())
        elif rule.type == "wildcard":
            base = rule.value.lower().lstrip("*.")
            domain_seeds.add(base)
        elif rule.type == "url":
            h = host_of(rule.value)
            if h:
                host_seeds.add(h)
                # The apex-ish domain is also a useful gau/subfinder seed.
                domain_seeds.add(h)
    return sorted(domain_seeds), sorted(host_seeds)


def extract_query_params(url: str) -> list[tuple[str, str]]:
    """Pull (name, value) pairs out of a URL's query string."""
    try:
        return parse_qsl(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return []


class ReconPipeline:
    def __init__(self, ctx: PlatformContext, logger: logging.Logger | None = None) -> None:
        self.ctx = ctx
        self.log = logger or logging.getLogger("recon.pipeline")
        self.tools = ReconTools(ctx.config, logger=self.log)
        self.ds = ctx.datastore
        self.pid = ctx.program_id

    def run(
        self,
        crawl_depth: int = 2,
        arjun_sample: int = 8,
        max_urls_per_source: int = 3000,
        seed_urls: list[str] | None = None,
        do_subfinder: bool = True,
        do_httpx: bool = True,
        do_gau: bool = True,
        do_katana: bool = True,
        do_arjun: bool = True,
    ) -> dict:
        cfg = self.ctx.config
        active_allowed = cfg.rules.automated_scanning_allowed
        if not active_allowed:
            self.log.warning(
                "automated_scanning_allowed=false for %r — running PASSIVE recon "
                "only (subfinder, gau, param extraction). Skipping httpx, katana, arjun.",
                cfg.name,
            )

        domain_seeds, host_seeds = derive_seeds(self.ctx)
        self.log.info("Seeds: domains=%s hosts=%s", domain_seeds, host_seeds)

        stats = {
            "subdomains": 0, "live_hosts": 0, "urls": 0, "parameters": 0, "hidden_params": 0,
        }

        # --- 1) subfinder (passive): subdomains ---
        hosts: set[str] = set(host_seeds)
        if do_subfinder:
            for d in domain_seeds:
                subs = self.tools.subfinder(d)
                for s in subs:
                    hosts.add(s)
                    self.ds.add_asset(self.pid, s, type_="host", source="subfinder")
                stats["subdomains"] += len(subs)

        # Record the seed hosts as assets too.
        for h in host_seeds:
            self.ds.add_asset(self.pid, h, type_="host", source="seed")

        # --- 2) httpx (ACTIVE): which hosts are live ---
        live_urls: list[str] = []
        if active_allowed and do_httpx:
            live = self.tools.httpx(sorted(hosts))
            for obj in live:
                url = obj.get("url") or ""
                if not url:
                    continue
                live_urls.append(url)
                self.ds.add_asset(
                    self.pid, host_of(url), type_="host", source="httpx",
                    is_live=True,
                    metadata={
                        "status_code": obj.get("status_code"),
                        "title": obj.get("title"),
                        "tech": obj.get("tech"),
                        "content_type": obj.get("content_type"),
                    },
                )
                self.ds.add_url(
                    self.pid, url, host=host_of(url),
                    status_code=obj.get("status_code"),
                    content_type=str(obj.get("content_type", "")),
                    source="httpx",
                )
            stats["live_hosts"] = len(live)
        else:
            # Without active probing we treat seed/url hosts as candidate roots.
            for h in sorted(hosts):
                live_urls.append(f"https://{h}/")

        # Explicit seed URLs (e.g. a known local app on a non-standard port).
        # They must pass scope, and they become crawl roots + stored URLs.
        for su in seed_urls or []:
            if self.ctx.config.scope.check(su).allowed:
                live_urls.append(su)
                self.ds.add_url(self.pid, su, host=host_of(su), source="seed-url")
            else:
                self.log.warning("Ignoring out-of-scope seed URL: %s", su)

        # --- 3) gau (passive): archived URLs ---
        harvested: set[str] = set()
        if do_gau:
            for d in domain_seeds:
                for u in self.tools.gau(d, max_urls=max_urls_per_source):
                    harvested.add(u)

        # --- 4) katana (ACTIVE): crawl live hosts ---
        if active_allowed and do_katana:
            for root in live_urls:
                for u in self.tools.katana(root, depth=crawl_depth, max_urls=max_urls_per_source):
                    harvested.add(u)

        # Store all harvested URLs.
        for u in harvested:
            self.ds.add_url(self.pid, u, host=host_of(u), source="harvest")
        stats["urls"] = len(harvested) + len(live_urls)

        # --- 5) query-param extraction (passive) ---
        param_count = 0
        for u in harvested:
            for name, value in extract_query_params(u):
                self.ds.add_parameter(
                    self.pid, u, name, param_type="query",
                    example_value=value, source="url-derived",
                )
                param_count += 1
        stats["parameters"] = param_count

        # --- 6) arjun (ACTIVE): hidden parameters on a sample ---
        if active_allowed and do_arjun and arjun_sample > 0:
            # Sample endpoints WITHOUT existing query params (most to gain there).
            candidates = [u for u in harvested if "?" not in u][:arjun_sample]
            if not candidates:
                candidates = live_urls[:arjun_sample]
            hidden = 0
            for u in candidates:
                for p in self.tools.arjun(u):
                    self.ds.add_parameter(
                        self.pid, u, p, param_type="query", source="arjun"
                    )
                    hidden += 1
            stats["hidden_params"] = hidden

        self.log.info("Recon complete: %s", stats)
        return stats
