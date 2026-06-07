"""
gaps.py — turn the misses into a to-do list for improving the modules.

For every false negative (and known-manual / no-module entry), classify it:
  fixable_tool_gap  — a module SHOULD have found it but didn't (or there's no
                      module yet). This is the actionable backlog.
  tuning_gap        — it WAS detected, just below the confidence threshold
                      (recommend tuning or improving the confidence signal).
  inherently_manual — needs human creativity; acceptable to miss.
"""

from __future__ import annotations

from dataclasses import dataclass

from validation.scoring import Result


@dataclass
class Gap:
    classification: str
    module: str
    target: str
    vuln_class: str
    location: str
    manifest_id: str
    note: str
    action: str


def build_gap_log(results: list[Result]) -> list[Gap]:
    gaps: list[Gap] = []
    for r in results:
        if r.status == "fn":
            gaps.append(Gap("fixable_tool_gap", r.module, r.target, r.vuln_class, r.location,
                            r.manifest_id, r.note,
                            f"The {r.module or 'relevant'} module missed this entirely — "
                            f"investigate discovery/confirmation for {r.vuln_class}."))
        elif r.status == "surfaced_low":
            gaps.append(Gap("tuning_gap", r.module, r.target, r.vuln_class, r.location,
                            r.manifest_id, r.note,
                            f"Detected at confidence {r.confidence} (below threshold) — "
                            f"lower the threshold or strengthen the confidence signal."))
        elif r.status == "no_module":
            gaps.append(Gap("fixable_tool_gap", r.module or "(none)", r.target, r.vuln_class,
                            r.location, r.manifest_id, r.note,
                            f"No module exists for {r.vuln_class} yet — candidate for a new module."))
        elif r.status == "human_puzzle":
            gaps.append(Gap("inherently_manual", r.module, r.target, r.vuln_class, r.location,
                            r.manifest_id, r.note,
                            "Requires manual creativity — acceptable miss; test by hand."))
    return gaps
