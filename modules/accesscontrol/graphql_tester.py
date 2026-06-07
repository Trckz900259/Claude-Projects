"""
graphql_tester.py — GraphQL authorization tester.

GraphQL collapses many objects behind one endpoint and one schema, so broken
object/function-level authorization (BOLA/BFLA) is rampant. We:

  1. DISCOVER the endpoint (probe /graphql, /api/graphql, /v1/graphql, /query).
  2. RECOVER the schema via __schema introspection; if it's disabled, we note it
     and point at clairvoyance / InQL (field-suggestion-based reconstruction).
  3. RESOLVER-LEVEL BOLA: for every id-accepting field, query it as the owner
     (baseline) and as another identity / anon, and compare with the decision
     engine — exactly like REST IDOR, reusing your own two accounts.
  4. BATCHING / ALIASING: check whether array batching and aliased fields are
     limited (unrestricted aliasing enables enumeration + rate-limit/2FA bypass).

All queries go through the scope-guarded session manager (identity-aware).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from modules.accesscontrol.decision import compare_access, sensitive_values

_COMMON_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
                 "/query", "/api/graphql/v1", "/gql"]

_INTROSPECTION = "{__schema{queryType{name} types{name fields{name args{name}}}}}"


@dataclass
class GraphQLFinding:
    kind: str            # introspection | bola | batching | bfla
    title: str
    detail: str
    severity: str
    cwe: str
    request: str = ""
    response: str = ""
    evidence: dict = field(default_factory=dict)


class GraphQLTester:
    def __init__(self, session_manager, logger: logging.Logger | None = None) -> None:
        self.sm = session_manager
        self.log = logger or logging.getLogger("ac.graphql")

    def _query(self, identity: str, url: str, query: str):
        res = self.sm.request_as(identity, "POST", url, json={"query": query},
                                 headers={"Content-Type": "application/json"})
        return res

    def discover(self, base_url: str) -> str | None:
        """Probe common paths; return the first that looks like GraphQL."""
        ident = self.sm.names()[0]
        for path in _COMMON_PATHS:
            url = base_url.rstrip("/") + path
            try:
                res = self.sm.request_as(ident, "POST", url, json={"query": "{__typename}"},
                                         headers={"Content-Type": "application/json"})
            except Exception:
                continue
            body = (res.text or "").lower()
            if res.status_code < 500 and ("data" in body or "errors" in body or "__typename" in body):
                self.log.info("GraphQL endpoint found: %s", url)
                return url
        return None

    def test(self, base_url: str) -> list[GraphQLFinding]:
        url = self.discover(base_url)
        if not url:
            return []
        findings: list[GraphQLFinding] = []

        # 2) introspection
        ident = self.sm.names()[0]
        intro = self._query(ident, url, _INTROSPECTION)
        id_fields: list[str] = []
        if intro.status_code < 300 and "__schema" in (intro.text or ""):
            findings.append(GraphQLFinding(
                "introspection", "GraphQL introspection is enabled",
                "The full schema is retrievable via __schema, aiding an attacker in "
                "mapping every type, field, and argument.", "low", "CWE-200",
                request=_INTROSPECTION, response=(intro.text or "")[:400]))
            id_fields = self._id_fields(intro.text or "")
        else:
            findings.append(GraphQLFinding(
                "introspection", "Introspection disabled (recover via clairvoyance/InQL)",
                "Introspection is off; reconstruct the schema from error-message field "
                "suggestions using clairvoyance / InQL.", "info", "CWE-200"))
            id_fields = ["user", "node"]  # common guesses

        # 3) resolver-level BOLA across your own accounts
        findings.extend(self._test_bola(url, id_fields))

        # 4) batching / aliasing
        findings.extend(self._test_batching(url, id_fields))
        return findings

    def _id_fields(self, introspection_json: str) -> list[str]:
        import json
        out: list[str] = []
        try:
            schema = json.loads(introspection_json)["data"]["__schema"]
            for t in schema.get("types", []):
                for f in (t.get("fields") or []):
                    if any((a.get("name") or "").lower() in ("id", "uid", "userid")
                           for a in (f.get("args") or [])):
                        out.append(f["name"])
        except Exception:
            pass
        return sorted(set(out)) or ["user"]

    def _test_bola(self, url: str, id_fields: list[str]) -> list[GraphQLFinding]:
        out: list[GraphQLFinding] = []
        auth = [p.name for p in self.sm.authenticated()]
        anon = [p.name for p in self.sm.profiles.values() if p.is_anonymous]
        for field_name in id_fields[:3]:
            for owner in auth:
                for oid in (self.sm.get(owner).owned_ids or [])[:1]:
                    q = f"{{ {field_name}(id: {oid}) {{ id name email secret role }} }}"
                    owner_res = self._query(owner, url, q)         # baseline
                    for attacker in [a for a in auth + anon if a != owner]:
                        atk = self._query(attacker, url, q)
                        markers = sensitive_values(owner_res.text)
                        cmp = compare_access(owner_res.status_code, owner_res.text,
                                             atk.status_code, atk.text, markers)
                        if cmp.tier == "no-finding":
                            continue
                        is_anon = self.sm.get(attacker).is_anonymous
                        out.append(GraphQLFinding(
                            "bola",
                            f"GraphQL BOLA: '{attacker}' read '{owner}'s {field_name}(id:{oid})",
                            f"Resolver '{field_name}' returns another account's private data "
                            f"with no object-level authorization (confidence {cmp.confidence}, "
                            f"similarity {cmp.similarity}). Both accounts are mine.",
                            "high" if cmp.sensitive_leaked else "medium",
                            "CWE-639" if not is_anon else "CWE-862",
                            request=q, response=(atk.text or "")[:300],
                            evidence={"confidence": cmp.confidence, "similarity": cmp.similarity,
                                      "tier": cmp.tier, "owner_response": owner_res.text[:300],
                                      "attacker_response": atk.text[:300]}))
        return out

    def _test_batching(self, url: str, id_fields: list[str]) -> list[GraphQLFinding]:
        field_name = id_fields[0] if id_fields else "user"
        # aliased batch of distinct ids in ONE request
        q = ("{ " + " ".join(f"a{i}: {field_name}(id: {i}) {{ id }}" for i in range(1, 6)) + " }")
        res = self.sm.request_as(self.sm.names()[0], "POST", url, json={"query": q},
                                 headers={"Content-Type": "application/json"})
        body = res.text or ""
        resolved = sum(1 for i in range(1, 6) if f'"a{i}"' in body or f"a{i}" in body)
        if resolved >= 3:
            return [GraphQLFinding(
                "batching", "Unrestricted query batching / aliasing",
                f"A single request resolved {resolved} aliased '{field_name}' lookups. "
                "Unlimited aliasing/batching enables amplified enumeration and "
                "rate-limit / 2FA brute-force bypass.", "medium", "CWE-770",
                request=q, response=body[:300],
                evidence={"resolved_aliases": resolved})]
        return []
