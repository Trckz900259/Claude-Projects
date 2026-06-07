"""
threshold.py — recommend a confidence threshold per module from the FP/FN data.

We sweep the confidence cutoff and, per module, compute precision/recall/F1 at
each value, then recommend the threshold that maximises F1 (i.e. balances false
positives against false negatives). The recommendation is SURFACED, never
auto-applied.
"""

from __future__ import annotations

from dataclasses import dataclass

from validation.scoring import ManifestEntry, aggregate, match_target

_GRID = [0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


@dataclass
class ThresholdRec:
    module: str
    recommended: float
    f1: float
    precision: float
    recall: float
    curve: list[dict]


def recommend(per_target: list[tuple], manifest: list[ManifestEntry]) -> list[ThresholdRec]:
    """
    per_target: list of (target_name, [finding dicts]).
    Returns one recommendation per module that appears in the manifest.
    """
    modules = sorted({e.module for e in manifest if e.module})
    recs: list[ThresholdRec] = []
    for module in modules:
        curve = []
        best = None
        for t in _GRID:
            results = []
            for target_name, findings in per_target:
                results.extend(match_target(target_name, findings, manifest, threshold=t))
            agg = aggregate(results)
            m = agg["by_module"].get(module, {})
            p = m.get("precision")
            r = m.get("recall")
            f1 = round(2 * p * r / (p + r), 3) if p and r else 0.0
            point = {"threshold": t, "precision": p, "recall": r, "f1": f1}
            curve.append(point)
            if best is None or f1 > best["f1"]:
                best = point
        if best:
            recs.append(ThresholdRec(module, best["threshold"], best["f1"],
                                     best["precision"] or 0.0, best["recall"] or 0.0, curve))
    return recs
