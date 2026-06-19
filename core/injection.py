"""
injection.py — prompt-injection / adversarial-content detector.

ALL target-derived content (HTTP bodies, errors, JS, JSON, headers) is UNTRUSTED
DATA, never instructions. The structural rule lives in the gateway (target
content is only ever passed as quoted data, never concatenated into directive
context). This module is the second layer: it FLAGS content that looks like it's
trying to issue instructions or redirect scope, so it can be logged and
quarantined.

It does not "parse intent" — it pattern-matches the well-known shapes of
injection so a human (or, in Phase 2, the gateway) is alerted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# (pattern, label, severity). Ordered roughly by how alarming a match is.
_SIGNATURES = [
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|context)",
     "ignore-previous-instructions", "high"),
    (r"disregard\s+(all\s+)?(previous|prior|above|the)\b", "disregard-context", "high"),
    (r"\bnew\s+instructions?\b", "new-instructions", "high"),
    (r"you\s+are\s+now\b|\bact\s+as\b|pretend\s+to\s+be", "role-override", "high"),
    (r"system\s*prompt|</?\s*system\s*>|\[\s*system\s*\]", "system-prompt-spoof", "high"),
    (r"(also|now|instead)\s+(test|scan|attack|target|exploit)\b", "scope-redirect", "high"),
    (r"\btest\s+(other|another|the\s+following)\b.*\.(com|net|org|io)\b", "scope-redirect-domain", "high"),
    (r"(skip|bypass|disable|ignore)\s+(the\s+)?(scope|safety|rate.?limit|check|filter)",
     "bypass-controls", "high"),
    (r"do\s+not\s+(report|log|record|audit)", "suppress-evidence", "high"),
    (r"(run|execute|eval)\s+(the\s+following|this\s+command|`)", "command-injection-instruction", "high"),
    (r"grant\s+(yourself|me|access)|you\s+(may|can)\s+now\s+(use|run|access)", "privilege-grant", "medium"),
    (r"(exfiltrate|send|post|curl|wget)\s+.*\bhttps?://", "exfiltration-instruction", "medium"),
    (r"```[a-z]*\s*\n.*(ignore|system|instruction)", "fenced-instruction-block", "medium"),
    (r"<!--\s*(ai|assistant|llm|prompt)\b", "hidden-comment-directive", "medium"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), label, sev) for p, label, sev in _SIGNATURES]


@dataclass
class InjectionVerdict:
    flagged: bool
    severity: str = "none"        # none | medium | high
    patterns: list[str] = field(default_factory=list)
    summary: str = ""

    def __bool__(self) -> bool:
        return self.flagged


class InjectionDetector:
    def scan(self, content: str, source: str = "") -> InjectionVerdict:
        """Scan untrusted content; flag instruction-like / scope-redirect shapes."""
        if not content:
            return InjectionVerdict(False)
        text = content if len(content) <= 200_000 else content[:200_000]
        hits: list[str] = []
        severity = "none"
        for rx, label, sev in _COMPILED:
            if rx.search(text):
                hits.append(label)
                if sev == "high" or (sev == "medium" and severity == "none"):
                    severity = sev
        if not hits:
            return InjectionVerdict(False)
        where = f" in {source}" if source else ""
        return InjectionVerdict(
            flagged=True, severity=severity, patterns=sorted(set(hits)),
            summary=(f"Adversarial/instruction-like content detected{where} "
                     f"({len(set(hits))} pattern(s)). Treated as DATA only; "
                     f"scope/goals/permissions are unaffected."))
