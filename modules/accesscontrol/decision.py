"""
decision.py — the comparison / decision engine (the brains).

The single biggest source of false positives in access-control testing is
trusting status codes. A 200 can be an "access denied" page; a 403 page can leak
data. So we compare response CONTENT across identities, after normalising
volatile noise, and emit a CONFIDENCE SCORE and a review tier rather than a
binary verdict. We NEVER auto-confirm — every hit is surfaced for human review +
side-by-side verification.

The core question for an IDOR/BOLA test:
  "Did the attacker identity receive the SAME private object the legitimate owner
   sees, when it shouldn't have?"

We answer it by comparing the attacker's response to the OWNER's baseline
response (not to an error template), normalising volatile fields first.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field

# Volatile things to blank before comparing, so per-request noise doesn't look
# like a "difference" (or a spurious "match").
_VOLATILE_KEYS = {"csrf", "csrftoken", "_csrf", "nonce", "timestamp", "time",
                  "date", "iat", "exp", "nbf", "requestid", "request_id",
                  "traceid", "trace_id", "etag", "lastmodified"}
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\"',}\s]*")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Field names that indicate sensitive data (raise confidence + severity).
_SENSITIVE_KEYS = re.compile(
    r"(email|e-mail|ssn|social|phone|mobile|address|dob|birth|password|passwd|"
    r"secret|token|api[_-]?key|card|iban|account|salary|balance|private)", re.I)


@dataclass
class AccessComparison:
    violation: bool
    confidence: float          # 0.0 .. 1.0
    tier: str                  # high-confidence | needs-review | no-finding
    similarity: float          # normalised content similarity to owner baseline
    reason: str
    sensitive_leaked: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def _strip_volatile_json(obj):
    if isinstance(obj, dict):
        return {k: ("<v>" if k.lower() in _VOLATILE_KEYS else _strip_volatile_json(v))
                for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_strip_volatile_json(x) for x in obj]
    return obj


def normalize_body(text: str) -> str:
    """Return a normalised form of a response body for comparison."""
    text = text or ""
    try:
        parsed = json.loads(text)
        return json.dumps(_strip_volatile_json(parsed), sort_keys=True)
    except Exception:
        pass
    # Non-JSON: blank out timestamps and long hex/token-ish runs.
    text = _ISO_TS.sub("<ts>", text)
    text = _LONG_HEX.sub("<hex>", text)
    return text.strip()


def content_similarity(a: str, b: str) -> float:
    """0..1 similarity of two normalised bodies."""
    a, b = normalize_body(a), normalize_body(b)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def sensitive_fields(text: str) -> list[str]:
    """Names of sensitive-looking fields present in a (JSON) body."""
    out: list[str] = []
    try:
        obj = json.loads(text or "")
    except Exception:
        return out

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if _SENSITIVE_KEYS.search(str(k)):
                    out.append(str(k))
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)
    return sorted(set(out))


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------
def sensitive_values(text: str) -> list[str]:
    """The VALUES of sensitive-looking fields (used as owner private markers)."""
    out: list[str] = []
    try:
        obj = json.loads(text or "")
    except Exception:
        return out

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if _SENSITIVE_KEYS.search(str(k)) and isinstance(v, (str, int)):
                    s = str(v)
                    if len(s) >= 3:
                        out.append(s)
                walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(obj)
    return sorted(set(out))


def compare_access(
    owner_status: int, owner_body: str,
    attacker_status: int, attacker_body: str,
    owner_private_markers: list[str] | None = None,
) -> AccessComparison:
    """
    Decide whether the attacker improperly obtained the owner's object.

    owner_*    : the legitimate owner's response (the baseline of "what the
                 private object looks like").
    attacker_* : the attacker identity's response to the SAME object.
    owner_private_markers : known-private string values of the owner (e.g. their
                 email/secret) — if these appear in the attacker's body it's a
                 very strong leak signal.
    """
    # Hard enforcement → definitely no access.
    if attacker_status in (401, 403, 404):
        return AccessComparison(False, 0.0, "no-finding", 0.0,
                                f"attacker got {attacker_status} (access enforced)")
    if not (200 <= attacker_status < 300):
        return AccessComparison(False, 0.1, "no-finding", 0.0,
                                f"attacker status {attacker_status} (not a successful read)")

    similarity = content_similarity(owner_body, attacker_body)
    leaked = sensitive_fields(attacker_body)

    # If markers weren't supplied, derive the owner's private VALUES from the
    # baseline so the function is self-sufficient (matches how the module calls it).
    if owner_private_markers is None:
        owner_private_markers = sensitive_values(owner_body)

    # Strongest signal: the owner's PRIVATE values appear in the attacker's body.
    marker_hit = False
    if owner_private_markers:
        marker_hit = any(m and m in (attacker_body or "") for m in owner_private_markers)

    # Build a confidence score.
    confidence = 0.0
    reasons = []
    if owner_status and 200 <= owner_status < 300:
        # owner baseline is a real object; compare to it
        confidence += 0.55 * similarity
        reasons.append(f"content {similarity:.0%} similar to owner's private view")
    if marker_hit:
        confidence += 0.4
        reasons.append("owner's private value(s) present in attacker response")
    if leaked:
        confidence += 0.1
        reasons.append(f"sensitive fields exposed: {', '.join(leaked[:4])}")
    confidence = min(1.0, confidence)

    # A near-identical successful response to the owner's private object is a hit.
    violation = (similarity >= 0.85 and owner_status and 200 <= owner_status < 300) or marker_hit

    if confidence >= 0.8:
        tier = "high-confidence"
    elif confidence >= 0.4:
        tier = "needs-review"
    else:
        tier = "no-finding"
        violation = False

    return AccessComparison(
        violation=violation, confidence=round(confidence, 2), tier=tier,
        similarity=round(similarity, 2),
        reason="; ".join(reasons) or "no strong signal",
        sensitive_leaked=leaked,
    )
