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


def remediation_for(subtype: str, context: str) -> Remediation:
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
