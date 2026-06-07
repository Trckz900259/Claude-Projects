"""
csp.py — parse a Content-Security-Policy and flag weaknesses.

A strong CSP is a major XSS mitigation; a weak one is a finding in its own right
(and tells us whether an injected payload would even run). We parse the header
into directives and check for the classic gaps.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CSPIssue:
    severity: str   # info | low | medium | high
    directive: str
    issue: str
    detail: str


def parse_csp(header_value: str) -> dict[str, list[str]]:
    """Turn a CSP header string into {directive: [sources...]}."""
    policy: dict[str, list[str]] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        policy[name] = [t for t in tokens[1:]]
    return policy


def analyze_csp(header_value: str | None) -> list[CSPIssue]:
    """Return a list of weaknesses found in the CSP (empty = none / strong)."""
    if not header_value:
        return [
            CSPIssue(
                "low", "(none)", "No Content-Security-Policy",
                "There is no CSP, so the browser provides no defence-in-depth "
                "against injected scripts. (Often treated as informational on its "
                "own, but it removes a key XSS mitigation.)",
            )
        ]

    policy = parse_csp(header_value)
    issues: list[CSPIssue] = []

    # Which directive actually governs scripts?
    script_src = policy.get("script-src", policy.get("default-src", []))
    script_dir = "script-src" if "script-src" in policy else "default-src"

    if not script_src:
        issues.append(CSPIssue(
            "medium", script_dir, "No script-src or default-src",
            "Scripts are not restricted by the policy.",
        ))

    lowered = [s.lower() for s in script_src]

    if "'unsafe-inline'" in lowered and not any(
        s.startswith("'nonce-") or s.startswith("'sha") for s in lowered
    ):
        issues.append(CSPIssue(
            "high", script_dir, "'unsafe-inline' allows inline scripts",
            "Inline event handlers and <script> blocks execute, so the CSP does "
            "not stop reflected/DOM XSS. Use nonces or hashes instead.",
        ))

    if "'unsafe-eval'" in lowered:
        issues.append(CSPIssue(
            "medium", script_dir, "'unsafe-eval' allows eval()",
            "eval/Function/setTimeout(string) can run attacker-controlled code.",
        ))

    if "*" in lowered:
        issues.append(CSPIssue(
            "high", script_dir, "Wildcard '*' source",
            "Scripts may be loaded from any origin, defeating the policy.",
        ))

    for src in lowered:
        if src in ("http:", "https:", "data:"):
            issues.append(CSPIssue(
                "medium", script_dir, f"Broad scheme source '{src}'",
                "A scheme-wide source lets scripts come from many origins "
                "(or data: URIs), which is commonly bypassable.",
            ))

    if "object-src" not in policy and "default-src" not in policy:
        issues.append(CSPIssue(
            "low", "object-src", "Missing object-src",
            "Without object-src 'none', plugin content (e.g. Flash/SVG) can be a "
            "bypass vector.",
        ))

    if "base-uri" not in policy:
        issues.append(CSPIssue(
            "low", "base-uri", "Missing base-uri",
            "Without base-uri, an injected <base> tag can hijack relative URLs.",
        ))

    return issues
