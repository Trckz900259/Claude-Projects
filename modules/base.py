"""
base.py — the common interface EVERY vulnerability module implements.

This is what makes the platform extensible: to add a new bug class (SQLi, SSRF,
IDOR, ...) you write a module that subclasses `Module` and implements two
methods. The orchestrator then drives it across the whole in-scope surface,
fault-tolerantly and with rate limiting, exactly like it drives XSS.

The two methods:

  build_candidates() -> list[Candidate]
      Read the shared inventory (urls, parameters) and produce a flat list of
      INDEPENDENT things to test. Each candidate is tested on its own, so one
      failure or one hit never affects another.

  test_candidate(candidate) -> list[Finding]
      Test ONE candidate and return zero or more findings. This must not raise
      on ordinary failures (network errors etc.) — return [] instead — so the
      run keeps going. The orchestrator still guards it with try/except as a
      safety net.
"""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from core.context import PlatformContext
from core.datastore import Finding


@dataclass
class Candidate:
    """One independent unit of work for a module to test."""

    module: str
    data: dict = field(default_factory=dict)

    def key(self) -> str:
        """
        A stable id for this candidate. Used to deduplicate the queue and to make
        runs RESUMABLE: re-running skips candidates whose key is already 'done'.
        """
        blob = json.dumps(self.data, sort_keys=True, default=str)
        digest = hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]
        return f"{self.module}:{digest}"


class Module(ABC):
    """Base class for all vulnerability modules."""

    #: short machine name, e.g. "xss" — also the value stored on findings.
    name: str = "base"
    #: one-line human description, shown in the CLI.
    description: str = ""

    def __init__(self, ctx: PlatformContext, logger: logging.Logger | None = None) -> None:
        self.ctx = ctx
        self.log = logger or logging.getLogger(f"module.{self.name}")

    # -- the two methods every module must implement ----------------------
    @abstractmethod
    def build_candidates(self) -> list[Candidate]:
        ...

    @abstractmethod
    def test_candidate(self, candidate: Candidate) -> list[Finding]:
        ...

    # -- optional lifecycle hooks -----------------------------------------
    def setup(self) -> None:
        """Run once before any candidate (e.g. start a callback listener)."""

    def teardown(self) -> None:
        """Run once after all candidates (e.g. stop a listener, flush state)."""
