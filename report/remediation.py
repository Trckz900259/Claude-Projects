"""
remediation.py — context-specific XSS remediation guidance.

Generic "sanitize your input" advice is close to useless. The CORRECT fix
depends on the sink the data lands in, so we tailor the encoding advice to the
detected context, then add the defence-in-depth layers (CSP, Trusted Types for
DOM, framework auto-escaping, HttpOnly cookies) and the standard references.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The right OUTPUT ENCODING for each context (this is the primary fix).
_ENCODING_BY_CONTEXT = {
    "html_body": (
        "HTML-entity-encode the value before writing it into the page body. Encode "
        "at least & < > \" ' (e.g. &amp; &lt; &gt; &quot; &#x27;). In templates, use "
        "the framework's HTML-escaping output (never a 'raw'/'safe' filter here)."
    ),
    "attribute": (
        "Encode for the HTML-attribute context and ALWAYS quote attribute values. "
        "Entity-encode the quote character and angle brackets so the value cannot "
        "break out of the attribute. Never place untrusted data in an unquoted "
        "attribute or in an event-handler attribute (on*)."
    ),
    "js_string": (
        "Do not build JavaScript by concatenating untrusted data. If a value must "
        "reach script, serialise it as JSON (e.g. JSON.stringify, or your framework's "
        "JS-context escaping) so quotes and </script> sequences cannot break out. "
        "Prefer passing data via a data-* attribute or a JSON <script type=\"application/json\"> "
        "block your code reads, rather than interpolating into code."
    ),
    "url": (
        "Validate and encode URL values: allow only http/https (or relative) URLs, "
        "reject javascript:/data:/vbscript: schemes, and URL-encode the value. Never "
        "place untrusted data directly into href/src without scheme validation."
    ),
    "css": (
        "Avoid putting untrusted data into <style> or style attributes. If "
        "unavoidable, strict-allow-list the value and CSS-escape it; do not allow "
        "expression()/url()/@import with untrusted input."
    ),
    "dom": (
        "Fix this in the client-side JavaScript: stop the source flowing into the "
        "sink. Replace innerHTML/outerHTML/document.write with textContent or safe "
        "DOM APIs (createElement + setAttribute). If HTML is truly required, sanitise "
        "with a vetted library (e.g. DOMPurify) before insertion."
    ),
}


@dataclass
class Remediation:
    summary: str
    output_encoding: str
    defence_in_depth: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


_REFERENCES = [
    "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) — https://cwe.mitre.org/data/definitions/79.html",
    "OWASP Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "OWASP DOM based XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
    "OWASP Top 10 2021 A03: Injection — https://owasp.org/Top10/A03_2021-Injection/",
]


_AC_REFERENCES = [
    "CWE-639: Authorization Bypass Through User-Controlled Key (IDOR) — https://cwe.mitre.org/data/definitions/639.html",
    "CWE-862: Missing Authorization — https://cwe.mitre.org/data/definitions/862.html",
    "CWE-285: Improper Authorization — https://cwe.mitre.org/data/definitions/285.html",
    "OWASP API Security Top 10 (API1 BOLA, API3 BOPLA, API5 BFLA) — https://owasp.org/API-Security/",
    "OWASP Authorization Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
]

_AC_REMEDIATION = {
    "horizontal": ("Enforce server-side OBJECT-LEVEL authorization (IDOR/BOLA).",
        "On every request, verify the authenticated principal is permitted to access the "
        "specific object id — do not trust the id from the client. Deny by default. Prefer "
        "unguessable/indirect reference maps so ids aren't enumerable.",
        ["Centralise ownership checks in a policy layer, not per-controller.",
         "Add automated tests that a second account cannot read the first's objects."]),
    "graphql": ("Enforce per-RESOLVER object-level authorization in GraphQL.",
        "Apply authorization in each resolver (and on edges as well as nodes); never assume "
        "the schema hides data. Validate the caller may access every id argument.",
        ["Limit query depth/complexity and disable introspection in production.",
         "Limit aliasing/batching to stop amplified enumeration and 2FA/rate-limit bypass."]),
    "vertical": ("Enforce FUNCTION-LEVEL authorization (BFLA).",
        "Check the caller's role/permission for privileged functions server-side, deny by "
        "default. Do not rely on the UI hiding admin actions.",
        ["Separate admin routes behind enforced role middleware.",
         "Log and alert on privileged-function access."]),
    "unauthenticated": ("Require authentication on protected endpoints.",
        "Ensure the endpoint mandates a valid session/token before returning any data; deny "
        "by default for anonymous callers.", ["Add auth middleware coverage tests."]),
    "object_property": ("Stop mass assignment (BOPLA).",
        "Allow-list the fields a request may bind; never bind request bodies straight onto "
        "objects. Reject/ignore privileged fields (role, isAdmin, owner_id) from user input.",
        ["Use explicit DTOs / serializers with read-only privileged fields."]),
    "jwt": ("Validate JWTs strictly.",
        "Pin an explicit algorithm allow-list (reject alg:none and RS256<->HS256 confusion), "
        "always verify the signature with a strong secret/key, and validate exp/nbf/iss/aud. "
        "Reject attacker-controlled kid/jwk/jku.",
        ["Rotate signing keys; store them securely.",
         "Prefer short-lived tokens + server-side revocation."]),
    "403bypass": ("Enforce authorization in the APPLICATION, not just the proxy.",
        "Apply access control in the app layer so path tricks (/..;/, case, encoding) and "
        "spoofable headers (X-Forwarded-For, X-Original-URL) cannot bypass it. Normalise "
        "paths before authorization; never trust client IP headers for authz.",
        ["Test the documented bypass families in CI against protected routes."]),
    "race": ("Make limited/single-use operations ATOMIC.",
        "Serialise the check-and-act with database constraints (unique indexes), row locks "
        "(SELECT ... FOR UPDATE), atomic decrements, or idempotency keys so concurrent "
        "requests cannot all pass the check.",
        ["Add a per-resource lock or a DB unique constraint on the one-shot action."]),
}


_SSRF_REFERENCES = [
    "CWE-918: Server-Side Request Forgery — https://cwe.mitre.org/data/definitions/918.html",
    "OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "OWASP Top 10 — SSRF (A10:2021; A01:2025 Broken Access Control) — https://owasp.org/Top10/",
]

_SSRF_REMEDIATION = {
    "_default": ("Validate outbound URLs with an ALLOWLIST and pin DNS.",
        "Accept only an allow-list of schemes (https), hosts, and ports — never a "
        "blocklist. Resolve the host ONCE and connect to that exact IP (DNS pinning) "
        "to defeat rebinding; reject literal/encoded internal/link-local IPs "
        "(127.0.0.0/8, 169.254.0.0/16, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7). "
        "Disable unused URL schemes (gopher/dict/file/ftp/...). Do NOT follow "
        "user-controlled redirects. Send fetches from an isolated egress with no "
        "metadata/internal access.",
        ["Network-block 169.254.169.254 and 169.254.170.2 from app egress.",
         "Strip/decode and re-validate the URL after every redirect hop."]),
    "cloud-metadata": ("Enforce IMDSv2 and block the metadata endpoint.",
        "Require IMDSv2 (HttpTokens=required) with a low hop limit (1), or block "
        "169.254.169.254/169.254.170.2 at the host/network. Use least-privilege "
        "instance roles. Then fix the SSRF itself (allowlist + DNS pinning).",
        ["Rotate any exposed credentials immediately.",
         "Alert on metadata access from application processes."]),
    "internal-service": ("Fix the SSRF and harden the internal service.",
        "Allowlist outbound destinations (above) AND require auth + network "
        "segmentation on internal services. For Spring Boot, disable/secure "
        "Actuator (management.endpoints.web.exposure.include minimal; never expose "
        "heapdump/env/gateway unauthenticated).",
        ["Put internal services on a network the app egress cannot reach.",
         "Authenticate internal admin/management endpoints."]),
}


def remediation_for(subtype: str, context: str) -> Remediation:
    if subtype in ("ssrf", "blind-ssrf", "cloud-metadata", "internal-service"):
        key = subtype if subtype in _SSRF_REMEDIATION else "_default"
        summary, primary, defence = _SSRF_REMEDIATION[key]
        return Remediation(summary=summary, output_encoding=primary,
                           defence_in_depth=defence, references=_SSRF_REFERENCES)
    if subtype in _AC_REMEDIATION:
        summary, primary, defence = _AC_REMEDIATION[subtype]
        return Remediation(summary=summary, output_encoding=primary,
                           defence_in_depth=defence, references=_AC_REFERENCES)
    if subtype == "csp":
        return Remediation(
            summary=(
                "Harden the Content-Security-Policy. A strong CSP is defence-in-depth "
                "that significantly reduces the impact of any XSS that slips through."
            ),
            output_encoding=(
                "Set a strict policy, e.g. default-src 'self'; script-src 'self' with "
                "per-response nonces (script-src 'nonce-<random>'); object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'. Remove 'unsafe-inline' and "
                "'unsafe-eval'. Avoid wildcard and scheme-wide (https:/data:) sources."
            ),
            defence_in_depth=[
                "Adopt nonce- or hash-based script allow-listing instead of 'unsafe-inline'.",
                "Add Trusted Types (require-trusted-types-for 'script') to lock down DOM sinks.",
                "Consider report-uri/report-to to monitor violations before enforcing.",
            ],
            references=_REFERENCES,
        )

    encoding = _ENCODING_BY_CONTEXT.get(context, _ENCODING_BY_CONTEXT["html_body"])

    defence = [
        "Use your framework's contextual auto-escaping templates and avoid 'raw'/"
        "'safe'/|safe escapes for untrusted data.",
        "Deploy a strict Content-Security-Policy (nonce-based script-src; no "
        "'unsafe-inline'); object-src 'none'; base-uri 'none'.",
        "Set session cookies HttpOnly (and Secure + SameSite) so stolen-cookie "
        "impact via XSS is reduced.",
    ]
    if subtype == "dom":
        defence.insert(
            0,
            "Enable Trusted Types (Content-Security-Policy: require-trusted-types-for "
            "'script') so dangerous DOM sinks reject raw strings; route any HTML "
            "through a vetted sanitiser like DOMPurify.",
        )

    return Remediation(
        summary=(
            f"Apply correct, context-aware OUTPUT ENCODING for the {context} context "
            f"where the data is written, and add the defence-in-depth layers below."
        ),
        output_encoding=encoding,
        defence_in_depth=defence,
        references=_REFERENCES,
    )
