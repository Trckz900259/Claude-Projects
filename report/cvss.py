"""
cvss.py — a real CVSS v3.1 base-score calculator + sensible XSS defaults.

Rather than hardcode magic numbers, we implement the published CVSS 3.1 base
formula and feed it a representative vector per XSS subtype. You can read exactly
how the score is derived, and adjust the vector when a specific finding's impact
differs (e.g. stored XSS that reaches admins).

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Metric weights from the CVSS 3.1 spec.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


@dataclass
class CVSS:
    score: float
    vector: str
    rating: str


def rating_for(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _roundup(x: float) -> float:
    """CVSS 3.1 'roundup': round up to one decimal place."""
    return math.ceil(x * 10) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in vector.replace("CVSS:3.1/", "").split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    return metrics


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m.get("S") == "C"

    av = _AV[m["AV"]]
    ac = _AC[m["AC"]]
    ui = _UI[m["UI"]]
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


# Representative vectors per XSS subtype. Adjust per real-world impact.
_SUBTYPE_VECTORS = {
    # Reflected: needs the victim to follow a crafted link (UI:R). Runs in the
    # victim's browser security context (Scope:Changed). Limited C/I impact.
    "reflected": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # DOM: same exploitation profile as reflected.
    "dom": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    # Stored: fires when any user views the content (UI:N) — easier, broader.
    "stored": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    # Blind: stored-like, often hitting privileged viewers.
    "blind": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
}


def score_for_subtype(subtype: str) -> CVSS:
    """Return a CVSS object for an XSS subtype (csp -> informational, no CVSS)."""
    if subtype == "csp":
        return CVSS(0.0, "", "informational")
    vector = _SUBTYPE_VECTORS.get(subtype, _SUBTYPE_VECTORS["reflected"])
    score = base_score(vector)
    return CVSS(score=score, vector=vector, rating=rating_for(score))
