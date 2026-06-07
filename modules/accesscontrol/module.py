"""
module.py — the Broken Access Control module (REST core).

Implements the common Module interface. The core idea (fuzz-lightyear / RESTler
style) is replay + compare across identities, using ONLY your own accounts:

  * OBJECT ACCESS (horizontal IDOR/BOLA): the legitimate owner (e.g. UserA) reads
    its own object -> baseline. The attacker identity (UserB / anon) reads the
    SAME object. If the attacker gets the owner's private data, that's a
    violation. This naturally produces the side-by-side PoC.

  * CROSS-IDENTITY REPLAY (vertical BFLA / unauthenticated): replay a captured
    request under a lower-privilege / anonymous identity and see if it still
    succeeds on a privileged endpoint.

  * BOPLA (mass assignment): re-send a write to YOUR OWN object with extra
    unexpected fields (role/isAdmin/owner_id) and see if they're accepted.

Safety baked in: requires >= 2 of YOUR OWN accounts (own-accounts-only); the
"victim" object is always one of your own accounts; proofs are READ-ONLY (the
only writes target your own object, to test mass assignment); scope + rate limit
+ User-Agent inherited; the whole module refuses to run unless automated scanning
is permitted. Blind enumeration of strangers' ids is NOT done by default — only
the explicit, controlled sequential sweep you authorise (--sweep).
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from core.context import PlatformContext
from core.datastore import Finding
from modules.accesscontrol.decision import compare_access, sensitive_values
from modules.base import Candidate, Module

# Fields we try to inject for BOPLA / mass-assignment.
_BOPLA_FIELDS = {"role": "admin", "isAdmin": True, "is_admin": True,
                 "admin": True, "owner_id": 0, "verified": True}

# Path/body keywords that suggest a single-use or rate-limited security action
# worth race-testing (with my OWN fresh state).
_RACE_KEYWORDS = ("redeem", "coupon", "voucher", "promo", "gift", "withdraw",
                  "transfer", "balance", "invite", "retest", "claim", "apply",
                  "vote", "topup", "refund", "checkout", "purchase")


def _privileged_path(path: str) -> bool:
    p = (path or "").lower()
    return any(s in p for s in ("/admin", "/manage", "/internal", "/root", "/superuser"))


def _build_url(base_url: str, path_template: str, ident_id: str) -> str:
    path = path_template.replace("{id}", str(ident_id)).replace("{uuid}", str(ident_id))
    return f"{base_url.rstrip('/')}{path}"


class AccessControlModule(Module):
    name = "accesscontrol"
    description = "Broken Access Control: IDOR/BOLA, BFLA, BOPLA (+ JWT/race/403 sub-engines)."

    def __init__(
        self, ctx: PlatformContext, logger: logging.Logger | None = None,
        sweep: bool = False, sweep_span: int = 5, max_pairs: int = 50,
    ) -> None:
        super().__init__(ctx, logger)
        self.sweep = sweep            # controlled sequential sweep (opt-in)
        self.sweep_span = sweep_span
        self.max_pairs = max_pairs
        # Race targets are run SEQUENTIALLY in teardown (not in the concurrent
        # worker pool), because a race burst needs the timing to itself.
        self._race_targets: list[dict] = []
        # No network here — just loads profiles + persists metadata.
        self.sm = ctx.session_manager()

    # -- lifecycle --------------------------------------------------------
    def setup(self) -> None:
        self.ctx.require_automated_scanning("access-control scan")
        self.sm.require_min(2)        # OWN-ACCOUNTS-ONLY gate
        self.sm.prime()               # fetch/refresh tokens
        # Re-persist now that tokens are primed, so the dashboard shows real auth.
        self.sm.persist(self.ctx.datastore, self.ctx.program_id)

    def teardown(self) -> None:
        # Run race tests now, sequentially, with the concurrent pool finished, so
        # each burst has the timing window to itself (reliable single-packet /
        # last-byte sync). Findings go straight to the datastore.
        if self._race_targets:
            self.log.info("Running %d race test(s) sequentially (isolated)...",
                          len(self._race_targets))
        for d in self._race_targets:
            try:
                for finding in self._test_race(d):
                    self.ctx.datastore.record_finding(self.ctx.program_id, finding)
            except Exception as exc:
                self.log.warning("race test on %s failed: %s", d.get("url"), exc)

    # -- candidate generation ---------------------------------------------
    def build_candidates(self) -> list[Candidate]:
        # Fail fast on the safety gates before doing any work.
        self.ctx.require_automated_scanning("access-control scan")
        self.sm.require_min(2)

        ds, pid = self.ctx.datastore, self.ctx.program_id
        auth = [p.name for p in self.sm.authenticated()]
        anon = [p.name for p in self.sm.profiles.values() if p.is_anonymous]
        attackers = auth + anon
        candidates: list[Candidate] = []

        # --- OBJECT ACCESS (horizontal IDOR + vertical + unauth) ---
        endpoints = ds.get_endpoints(pid)
        id_endpoints = [e for e in endpoints if "{id}" in e["path_template"] or "{uuid}" in e["path_template"]]
        pairs = 0
        for ep in id_endpoints:
            if (ep["method"] or "GET").upper() != "GET":
                continue  # READ-ONLY proof: only read endpoints for object access
            for owner in auth:
                owner_ids = self.sm.get(owner).owned_ids or []
                for oid in owner_ids[:2]:
                    for attacker in attackers:
                        if attacker == owner:
                            continue
                        candidates.append(Candidate(self.name, {
                            "kind": "object_access",
                            "method": "GET",
                            "base_url": ep["base_url"],
                            "path_template": ep["path_template"],
                            "owner": owner, "attacker": attacker, "owner_id": str(oid),
                        }))
                        pairs += 1
                        if pairs >= self.max_pairs:
                            break

        # --- CROSS-IDENTITY REPLAY (vertical / unauthenticated) ---
        seen_eps: set[tuple] = set()
        for row in ds.get_captured(pid):
            method = (row["method"] or "GET").upper()
            # READ-ONLY proof: only replay safe (read) requests across identities.
            # Never re-send a captured POST/PUT/DELETE under another identity — that
            # could modify state or another account's data.
            if method != "GET":
                continue
            url = row["url"]
            key = (method, urlparse(url).path)
            if key in seen_eps:
                continue
            seen_eps.add(key)
            origin = row["captured_as"] or ""
            for attacker in attackers:
                if attacker == origin:
                    continue
                candidates.append(Candidate(self.name, {
                    "kind": "cross_replay", "method": method, "url": url,
                    "attacker": attacker, "origin": origin,
                }))

        # --- BOPLA (mass assignment, on your OWN object) ---
        for row in ds.get_captured(pid):
            method = (row["method"] or "GET").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            body = row["req_body"] or ""
            if not body.strip().startswith("{"):
                continue
            # Skip single-use/limited ACTION endpoints — those are tested by the
            # race engine; re-sending them here would consume that one-shot state.
            if any(k in urlparse(row["url"]).path.lower() for k in _RACE_KEYWORDS):
                continue
            ident = row["captured_as"] or (auth[0] if auth else "")
            if not ident:
                continue
            candidates.append(Candidate(self.name, {
                "kind": "bopla", "method": method, "url": row["url"],
                "identity": ident, "base_body": body,
            }))

        # --- RACE conditions (single-use / limited actions; OWN fresh state) ---
        captured = ds.get_captured(pid)
        for row in captured:
            method = (row["method"] or "GET").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            path = urlparse(row["url"]).path.lower()
            body = (row["req_body"] or "").lower()
            if any(k in path or k in body for k in _RACE_KEYWORDS):
                # Collected for the isolated teardown phase, NOT enqueued.
                self._race_targets.append({
                    "method": method, "url": row["url"],
                    "body": row["req_body"] or "", "req_headers": row["req_headers"]})

        # --- 403/401 bypass (endpoints observed returning forbidden) ---
        seen_forbidden: set[str] = set()
        for row in captured:
            if (row["status_code"] or 0) in (401, 403) and row["url"] not in seen_forbidden:
                seen_forbidden.add(row["url"])
                candidates.append(Candidate(self.name, {
                    "kind": "bypass", "url": row["url"], "baseline": row["status_code"]}))

        # --- JWT forgery (one candidate per distinct token in captured traffic) ---
        from core.tokens import harvest_traffic
        oracle = self._find_oracle(captured)
        if oracle:
            jwts = {t.value for t in harvest_traffic(captured) if t.type == "jwt"}
            for tok in jwts:
                candidates.append(Candidate(self.name, {
                    "kind": "jwt", "token": tok, "oracle_url": oracle}))

        # --- GraphQL authorization testing (one candidate per base host) ---
        bases: set[str] = set()
        for e in endpoints:
            if e["base_url"]:
                bases.add(e["base_url"])
        for row in captured:
            p = urlparse(row["url"])
            if p.scheme and p.netloc:
                bases.add(f"{p.scheme}://{p.netloc}")
        for b in sorted(bases):
            candidates.append(Candidate(self.name, {"kind": "graphql", "base_url": b}))

        # --- controlled sequential sweep (opt-in only) ---
        if self.sweep:
            candidates.extend(self._sweep_candidates(id_endpoints, auth))

        self.log.info("Built %d access-control candidates", len(candidates))
        return candidates

    @staticmethod
    def _find_oracle(captured) -> str:
        """Find a captured GET that echoes the caller's identity (e.g. /api/me)."""
        best = ""
        for row in captured:
            if (row["method"] or "GET").upper() != "GET":
                continue
            if not (200 <= (row["status_code"] or 0) < 300):
                continue
            path = row["url"].lower()
            if any(h in path for h in ("/me", "/profile", "/account", "/whoami", "/self")):
                return row["url"]
            if not best:
                best = row["url"]
        return best

    def _sweep_candidates(self, id_endpoints, auth) -> list[Candidate]:
        """Explicitly-authorised, controlled, READ-ONLY sequential id sweep."""
        out: list[Candidate] = []
        for ep in id_endpoints:
            if (ep["method"] or "GET").upper() != "GET":
                continue
            for owner in auth:
                for oid in (self.sm.get(owner).owned_ids or [])[:1]:
                    try:
                        base = int(oid)
                    except ValueError:
                        continue
                    for cand_id in range(max(1, base - self.sweep_span), base + self.sweep_span + 1):
                        out.append(Candidate(self.name, {
                            "kind": "sweep", "method": "GET",
                            "base_url": ep["base_url"], "path_template": ep["path_template"],
                            "owner": owner, "probe_id": str(cand_id),
                        }))
        return out

    # -- the work ---------------------------------------------------------
    def test_candidate(self, candidate: Candidate) -> list[Finding]:
        kind = candidate.data.get("kind")
        if kind == "object_access":
            return self._test_object_access(candidate.data)
        if kind == "cross_replay":
            return self._test_cross_replay(candidate.data)
        if kind == "bopla":
            return self._test_bopla(candidate.data)
        if kind == "sweep":
            return self._test_sweep(candidate.data)
        if kind == "jwt":
            return self._test_jwt(candidate.data)
        if kind == "race":
            return self._test_race(candidate.data)
        if kind == "bypass":
            return self._test_bypass(candidate.data)
        if kind == "graphql":
            return self._test_graphql(candidate.data)
        return []

    # ---- GraphQL authorization ----
    def _test_graphql(self, d: dict) -> list[Finding]:
        from modules.accesscontrol.graphql_tester import GraphQLTester

        findings: list[Finding] = []
        for r in GraphQLTester(self.sm, logger=self.log).test(d["base_url"]):
            findings.append(Finding(
                type="accesscontrol", subtype="graphql", severity=r.severity, status="new",
                url=d["base_url"], parameter=r.kind, context="graphql",
                payload=r.request, request=r.request, response=r.response,
                title=r.title, description=r.detail,
                evidence={**r.evidence, "classification": "graphql", "graphql_kind": r.kind,
                          "cwe": r.cwe, "tier": r.evidence.get("tier", "needs-review")},
            ))
        return findings

    # ---- race condition / limit overrun ----
    def _test_race(self, d: dict) -> list[Finding]:
        from core.race import RaceEngine

        try:
            headers = json.loads(d.get("req_headers") or "{}")
        except Exception:
            headers = {}
        send = {k: v for k, v in headers.items()
                if k.lower() in ("authorization", "content-type", "cookie")}
        eng = RaceEngine(self.ctx.config.scope, self.ctx.config.http.user_agent,
                         verify_tls=self.ctx.config.http.verify_tls, logger=self.log)
        res = eng.race(d["url"], method=d["method"], headers=send, body=d.get("body", ""), count=20)
        if res.successes <= 1:
            return []  # properly serialised — no race

        # IMPACT GATE: is the same outcome trivially achievable another way?
        account_scoped = any(k.lower() in ("authorization", "cookie") for k in send)
        if account_scoped:
            severity = "medium"
            impact = ("Account-scoped action: a fresh account might achieve the same "
                      "outcome — assess real business impact (could be low).")
        else:
            severity = "high"
            impact = "Global/unauthenticated single-use action over-applied — likely high impact."

        return [Finding(
            type="accesscontrol", subtype="race", severity=severity, status="new",
            url=d["url"], parameter="", context=f"race x{res.count} ({res.mode})",
            payload=f"{res.count} concurrent {d['method']} via {res.mode}",
            request=f"{d['method']} {d['url']}\n\n{d.get('body', '')}",
            response=f"status distribution: {res.status_distribution}; successes: {res.successes}",
            title=f"Race condition / limit-overrun: {res.successes}/{res.count} succeeded",
            description=(
                f"Firing {res.count} concurrent requests ({res.mode}) produced "
                f"{res.successes} successes on a single-use/limited action (expected 1). "
                f"{impact} Used my own fresh state only."),
            evidence={"classification": "race", "cwe": "CWE-362", "mode": res.mode,
                      "successes": res.successes, "count": res.count,
                      "status_distribution": res.status_distribution,
                      "impact_gate": impact, "tier": "needs-review"},
        )]

    # ---- 403 / access-control bypass ----
    def _test_bypass(self, d: dict) -> list[Finding]:
        from modules.accesscontrol.bypass import BypassTester

        results = BypassTester(self.ctx.http, logger=self.log).test(d["url"])
        wins = [r for r in results if r.bypassed]
        if not wins:
            return []
        techniques = ", ".join(f"{r.technique}({r.status})" for r in wins)
        return [Finding(
            type="accesscontrol", subtype="403bypass", severity="high", status="new",
            url=d["url"], parameter="", context="403-bypass",
            payload=techniques,
            request=f"GET {d['url']}  (+ bypass variants)",
            response="; ".join(f"{r.technique} -> {r.status}" for r in wins),
            title=f"403/401 bypass: {len(wins)} technique(s) reached the resource",
            description=(
                f"{d['url']} returns {d['baseline']} normally, but these bypasses returned "
                f"2xx: {techniques}. Authorization is enforced inconsistently (e.g. at the "
                f"proxy/path layer rather than in the application)."),
            evidence={"classification": "403bypass", "cwe": "CWE-863",
                      "baseline": d["baseline"], "tier": "high-confidence",
                      "working": [{"technique": r.technique, "detail": r.detail,
                                   "status": r.status} for r in wins]},
        )]

    # ---- JWT forgery ----
    def _test_jwt(self, d: dict) -> list[Finding]:
        from modules.accesscontrol.jwt_tester import JwtTester

        tester = JwtTester(self.ctx.http, logger=self.log)
        findings: list[Finding] = []
        for r in tester.test_token(d["token"], d["oracle_url"]):
            if not r.accepted:
                continue
            findings.append(Finding(
                type="accesscontrol", subtype="jwt",
                severity="high" if r.escalated_to else "medium", status="new",
                url=d["oracle_url"], parameter=r.test, context="jwt",
                payload=(r.forged_token or "")[:300],
                request=f"GET {d['oracle_url']}\nAuthorization: Bearer {(r.forged_token or '')[:60]}...",
                response=r.response_excerpt,
                title=f"JWT weakness: {r.test} accepted"
                      + (f" (escalated to {r.escalated_to})" if r.escalated_to else ""),
                description=r.detail,
                evidence={"classification": "jwt", "cwe": "CWE-347", "test": r.test,
                          "escalated_to": r.escalated_to,
                          "tier": "high-confidence" if r.escalated_to else "needs-review",
                          "forged_token": r.forged_token},
            ))
        return findings

    # ---- horizontal IDOR / vertical / unauth via side-by-side ----
    def _test_object_access(self, d: dict) -> list[Finding]:
        url = _build_url(d["base_url"], d["path_template"], d["owner_id"])
        owner, attacker = d["owner"], d["attacker"]

        owner_res = self.sm.request_as(owner, "GET", url)      # baseline (legit)
        attacker_res = self.sm.request_as(attacker, "GET", url)  # attack
        markers = sensitive_values(owner_res.text)
        cmp = compare_access(owner_res.status_code, owner_res.text,
                             attacker_res.status_code, attacker_res.text, markers)
        if cmp.tier == "no-finding":
            return []

        is_anon = self.sm.get(attacker).is_anonymous
        path = d["path_template"]
        if is_anon:
            subtype, cwe = "unauthenticated", "CWE-862"
        elif _privileged_path(path):
            subtype, cwe = "vertical", "CWE-862"  # BFLA
        else:
            subtype, cwe = "horizontal", "CWE-639"  # IDOR/BOLA
        severity = "high" if cmp.sensitive_leaked else ("high" if cmp.confidence >= 0.8 else "medium")

        return [Finding(
            type="accesscontrol", subtype=subtype, severity=severity, status="new",
            url=url, parameter=d["path_template"], context=f"owner={owner},attacker={attacker}",
            payload=f"{attacker} requested {owner}'s object {url}",
            request=attacker_res.request_as_text(), response=attacker_res.response_as_text(),
            title=f"{_label(subtype)}: {attacker} accessed {owner}'s object ({path})",
            description=(
                f"Identity '{attacker}' retrieved an object owned by '{owner}' at {url}. "
                f"Decision engine: {cmp.reason} (confidence {cmp.confidence}, similarity "
                f"{cmp.similarity}). Tier: {cmp.tier}. Both accounts are mine; the data "
                f"belongs to my own '{owner}' account."),
            cvss_vector="", evidence={
                "classification": subtype, "cwe": cwe,
                "confidence": cmp.confidence, "tier": cmp.tier, "similarity": cmp.similarity,
                "sensitive_leaked": cmp.sensitive_leaked,
                "owner_request": owner_res.request_as_text(),
                "owner_response": owner_res.response_as_text(),
                "attacker_request": attacker_res.request_as_text(),
                "attacker_response": attacker_res.response_as_text(),
            },
        )]

    # ---- vertical / unauthenticated via cross-identity replay ----
    def _test_cross_replay(self, d: dict) -> list[Finding]:
        attacker = d["attacker"]
        res = self.sm.request_as(attacker, d["method"], d["url"])
        if not (200 <= res.status_code < 300):
            return []
        path = urlparse(d["url"]).path
        is_anon = self.sm.get(attacker).is_anonymous
        # Only interesting if this looks privileged or auth-required.
        if not (_privileged_path(path) or is_anon):
            return []
        subtype = "unauthenticated" if is_anon else "vertical"
        cwe = "CWE-862"
        return [Finding(
            type="accesscontrol", subtype=subtype,
            severity="high" if _privileged_path(path) else "medium", status="new",
            url=d["url"], parameter="", context=f"attacker={attacker}",
            payload=f"{attacker} {d['method']} {d['url']} -> {res.status_code}",
            request=res.request_as_text(), response=res.response_as_text(),
            title=f"{_label(subtype)}: {attacker} reached {path} ({res.status_code})",
            description=(
                f"Identity '{attacker}' successfully called {d['method']} {d['url']} "
                f"(HTTP {res.status_code}) on what appears to be a privileged/auth-required "
                f"endpoint. Needs manual confirmation of the privilege boundary."),
            evidence={"classification": subtype, "cwe": cwe, "tier": "needs-review",
                      "attacker_response": res.response_as_text()},
        )]

    # ---- BOPLA / mass assignment (own object) ----
    def _test_bopla(self, d: dict) -> list[Finding]:
        try:
            base = json.loads(d["base_body"])
        except Exception:
            return []
        if not isinstance(base, dict):
            return []
        injected = {**base, **_BOPLA_FIELDS}
        ident = d["identity"]
        res = self.sm.request_as(ident, d["method"], d["url"],
                                 data=json.dumps(injected),
                                 headers={"Content-Type": "application/json"})
        # Did an injected privileged field get reflected/accepted?
        accepted = []
        for k, v in _BOPLA_FIELDS.items():
            if k in (res.text or "") and str(v) in (res.text or ""):
                accepted.append(k)
        if not accepted:
            return []
        return [Finding(
            type="accesscontrol", subtype="object_property", severity="high", status="new",
            url=d["url"], parameter=",".join(accepted), context=f"identity={ident}",
            payload=json.dumps(injected),
            request=res.request_as_text(), response=res.response_as_text(),
            title=f"BOPLA / mass assignment: injected {', '.join(accepted)} accepted",
            description=(
                f"Sending {d['method']} {d['url']} with unexpected field(s) "
                f"{', '.join(accepted)} (on my OWN object) was accepted/reflected, "
                f"indicating object-property-level authorization is missing (mass "
                f"assignment / privilege escalation in one call)."),
            evidence={"classification": "object_property", "cwe": "CWE-915",
                      "injected_fields": accepted, "tier": "needs-review",
                      "attacker_response": res.response_as_text()},
        )]

    # ---- controlled sequential sweep (opt-in) ----
    def _test_sweep(self, d: dict) -> list[Finding]:
        owner = d["owner"]
        url = _build_url(d["base_url"], d["path_template"], d["probe_id"])
        res = self.sm.request_as(owner, "GET", url)
        if not (200 <= res.status_code < 300):
            return []
        # We only REPORT ids that aren't ours, as reachability evidence (read-only).
        if self.sm.is_own_id(d["probe_id"]):
            return []
        return [Finding(
            type="accesscontrol", subtype="horizontal", severity="medium", status="new",
            url=url, parameter=d["path_template"], context="sequential-sweep",
            payload=f"sequential probe id={d['probe_id']}",
            request=res.request_as_text(), response=res.response_as_text(),
            title=f"Sequential id {d['probe_id']} reachable (authorised sweep)",
            description=(
                f"During the authorised, controlled sweep, id {d['probe_id']} returned "
                f"{res.status_code} — a foreign object appears reachable. READ-ONLY proof; "
                f"confirm the boundary manually."),
            evidence={"classification": "horizontal", "cwe": "CWE-639",
                      "tier": "needs-review", "probe_id": d["probe_id"]},
        )]


def _label(subtype: str) -> str:
    return {"horizontal": "Horizontal IDOR/BOLA", "vertical": "Vertical BFLA",
            "unauthenticated": "Unauthenticated access",
            "object_property": "BOPLA / mass assignment"}.get(subtype, subtype)
