"""
scoring.py — match findings against the ground-truth manifest and compute metrics.

It is THRESHOLD-PARAMETERISED so Stage 6 can sweep the confidence cutoff. Each
finding gets a uniform 0..1 confidence; at a threshold T:

  tp            a findable manifest entry matched by a finding with conf >= T
  fn            a findable entry not matched at all (a true miss)
  surfaced_low  a findable entry matched only by a finding with conf < T
                (detected, but below the auto-confirm bar -> counts against recall
                 at T, but is NOT a true miss — it's in the review queue)
  fp            a finding with conf >= T that matches no manifest entry
  needs_review  a finding with conf < T that matches nothing (the review queue)
  human_puzzle  a known-manual entry (excluded from the FN penalty)
  no_module     a real bug with no module yet (excluded; surfaced in the gap log)
  info          low-value noise (csp/info) — excluded from precision

precision = tp / (tp + fp)      recall = tp / (tp + surfaced_low + fn)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

DEFAULT_THRESHOLD = 0.7
_MODULE_OF = {"xss": "xss", "accesscontrol": "accesscontrol", "ssrf": "ssrf"}


@dataclass
class ManifestEntry:
    id: str
    target: str
    finding_type: str
    subtype: str
    endpoint: str
    param: str
    severity: str
    kind: str            # findable | human_puzzle | no_module
    module: str
    note: str


@dataclass
class Result:
    status: str
    module: str
    target: str
    vuln_class: str
    location: str
    manifest_id: str = ""
    finding_id: int | None = None
    confidence: float | None = None
    note: str = ""


def load_manifest(path: str | Path) -> list[ManifestEntry]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out = []
    for e in data.get("entries", []):
        out.append(ManifestEntry(
            id=str(e["id"]), target=e["target"], finding_type=e["finding_type"],
            subtype=str(e.get("subtype", "")), endpoint=str(e.get("endpoint", "")),
            param=str(e.get("param", "")), severity=str(e.get("severity", "")),
            kind=str(e.get("kind", "findable")), module=str(e.get("module", "")),
            note=str(e.get("note", ""))))
    return out


def finding_confidence(f) -> float:
    """A uniform 0..1 confidence from status/tier/confidence across modules."""
    status = f["status"] if "status" in f.keys() else f.get("status")
    if status == "verified":
        return 1.0
    try:
        ev = json.loads(f["evidence"] or "{}")
    except Exception:
        ev = {}
    if isinstance(ev.get("confidence"), (int, float)):
        return float(ev["confidence"])
    tier = ev.get("tier", "")
    return {"confirmed": 0.95, "high-confidence": 0.9, "needs-review": 0.5}.get(tier, 0.4)


def _path(url: str) -> str:
    return urlparse(url or "").path


def _matches(f, e: ManifestEntry) -> bool:
    if f["type"] != e.finding_type:
        return False
    if e.subtype and (f["subtype"] or "") != e.subtype:
        return False
    if e.endpoint and e.endpoint not in (f["url"] or ""):
        return False
    if e.param:
        hay = f"{f['parameter'] or ''} {f['context'] or ''} {f['url'] or ''}".lower()
        if e.param.lower() not in hay:
            return False
    return True


def _is_noise(f) -> bool:
    return (f["subtype"] or "") == "csp" or (f["severity"] or "") == "info"


def match_target(target: str, findings: list, entries: list[ManifestEntry],
                 threshold: float = DEFAULT_THRESHOLD) -> list[Result]:
    findings = list(findings)
    entries = [e for e in entries if e.target == target]
    findable = [e for e in entries if e.kind == "findable"]
    other = [e for e in entries if e.kind in ("human_puzzle", "no_module")]
    results: list[Result] = []
    claimed: set[int] = set()

    # Match the most-specific findable entries first.
    for e in sorted(findable, key=lambda x: -(bool(x.param) + bool(x.subtype))):
        match = next((f for f in findings if id(f) not in claimed and _matches(f, e)), None)
        loc = f"{e.endpoint} {e.param}".strip()
        if match is not None:
            claimed.add(id(match))
            conf = finding_confidence(match)
            status = "tp" if conf >= threshold else "surfaced_low"
            results.append(Result(status, e.module, target, f"{e.finding_type}/{e.subtype}",
                                  loc, e.id, match["id"], conf, e.note))
        else:
            results.append(Result("fn", e.module, target, f"{e.finding_type}/{e.subtype}",
                                  loc, e.id, None, None, e.note))

    # human_puzzle / no_module: bonus credit if found, else list (not penalised).
    for e in other:
        match = next((f for f in findings if id(f) not in claimed and _matches(f, e)), None)
        loc = f"{e.endpoint} {e.param}".strip()
        if match is not None:
            claimed.add(id(match))
            results.append(Result("tp", e.module or _MODULE_OF.get(e.finding_type, ""),
                                  target, f"{e.finding_type}/{e.subtype}", loc, e.id,
                                  match["id"], finding_confidence(match), "bonus: " + e.note))
        else:
            results.append(Result(e.kind, e.module, target, f"{e.finding_type}/{e.subtype}",
                                  loc, e.id, None, None, e.note))

    # Unclaimed findings: duplicate (re-confirms a known vuln), FP, needs_review, info.
    for f in findings:
        if id(f) in claimed:
            continue
        module = _MODULE_OF.get(f["type"], f["type"])
        loc = f"{_path(f['url'])} {f['parameter'] or ''}".strip()
        if _is_noise(f):
            results.append(Result("info", module, target, f"{f['type']}/{f['subtype']}",
                                  loc, "", f["id"], finding_confidence(f), "low-value noise"))
            continue
        # A finding that re-confirms a manifest vuln (e.g. IDOR from the reverse
        # identity direction) is a DUPLICATE, not a false positive.
        if any(_matches(f, e) for e in findable):
            results.append(Result("duplicate", module, target, f"{f['type']}/{f['subtype']}",
                                  loc, "", f["id"], finding_confidence(f),
                                  "re-confirms a known vuln (not a false positive)"))
            continue
        conf = finding_confidence(f)
        status = "fp" if conf >= threshold else "needs_review"
        results.append(Result(status, module, target, f"{f['type']}/{f['subtype']}",
                              loc, "", f["id"], conf, f["title"] if "title" in f.keys() else ""))
    return results


def aggregate(results: list[Result]) -> dict:
    """Per-module and per-class precision/recall + overall."""
    def bucket():
        return {"tp": 0, "fp": 0, "fn": 0, "surfaced_low": 0, "needs_review": 0,
                "human_puzzle": 0, "no_module": 0, "info": 0, "duplicate": 0}

    by_module: dict[str, dict] = {}
    by_class: dict[str, dict] = {}
    overall = bucket()
    for r in results:
        for key, store in ((r.module or "?", by_module), (r.vuln_class, by_class)):
            store.setdefault(key, bucket())
            if r.status in store[key]:
                store[key][r.status] += 1
        if r.status in overall:
            overall[r.status] += 1

    def finalize(b: dict) -> dict:
        tp, fp = b["tp"], b["fp"]
        fn = b["fn"] + b["surfaced_low"]
        b["precision"] = round(tp / (tp + fp), 3) if (tp + fp) else None
        b["recall"] = round(tp / (tp + fn), 3) if (tp + fn) else None
        return b

    return {
        "overall": finalize(overall),
        "by_module": {k: finalize(v) for k, v in by_module.items()},
        "by_class": {k: finalize(v) for k, v in by_class.items()},
    }
