"""
usage.py — the "Usage Governor": a standalone budget controller for LLM/agent usage.

Why this matters: a bug-bounty platform that drives Large Language Models (LLMs)
or autonomous agents can quietly burn through a token/credit budget. If it spends
everything, there is nothing left for the *human* operator who wants to ask the
assistant a question interactively. The Usage Governor prevents that by tracking
consumption against TWO budgets at once and HALTING automated spend before the
budget is exhausted — deliberately leaving a slice of headroom (15% by default)
reserved for interactive use.

The two budgets:

  * DAILY budget   — a cap per UTC calendar day. Resets automatically at UTC
                     midnight because we only ever sum *today's* events.
  * ROLLING budget — a cap over the most recent `rolling_window_seconds` (a
                     sliding window, e.g. the last hour). This catches bursts
                     that a daily cap would miss.

We HALT automated usage at `halt_threshold = 1 - reserve_fraction` (so 0.85, i.e.
85%) of EITHER budget. Whichever cap is hit first wins. The remaining 15% is the
operator's reserved headroom.

"Budget" is measured in TOKENS (a floating-point count). Request counts and a
monetary `cost` are tracked too, but only as auxiliary/informational counters —
the halt decision is driven purely by tokens.

Design notes:
  * This module is deliberately STANDALONE: it imports nothing from `core/*`.
    You can lift it into another project as a single file.
  * State (the event log) is persisted as JSON to a configurable path
    (default `data/usage.json`). Parent directories are created as needed, and
    a missing or corrupt file simply starts fresh rather than crashing.
  * Several methods accept an optional `now: datetime` argument. This is purely
    for testability — passing an explicit "current time" lets tests simulate the
    passage of time deterministically. In normal use you omit it and the real
    UTC clock is used.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _parse_ts(ts: str) -> datetime:
    """
    Parse an ISO-8601 timestamp string back into a timezone-aware UTC datetime.

    We always *write* timestamps in UTC (see `record`), but we are defensive on
    read: if an old/edited record has no timezone we assume UTC, and if it cannot
    be parsed at all we return a far-past time so it is treated as "very old"
    (and therefore pruned / ignored) rather than crashing the whole governor.
    """
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class UsageDecision:
    """
    The result of asking the governor "may I spend right now?".

    Fields:
      allowed        — True if automated usage is permitted; False if we should HALT.
      reason         — Human-readable explanation of *why* (which cap, if any, is hit).
      daily_used     — Tokens consumed so far today (UTC calendar day).
      daily_limit    — The configured daily token budget.
      rolling_used   — Tokens consumed within the rolling window.
      rolling_limit  — The configured rolling-window token budget.
      daily_pct      — Fraction of the daily budget used (used / limit; 0.0 if unlimited).
      rolling_pct    — Fraction of the rolling budget used (used / limit; 0.0 if unlimited).
      halt_threshold — The fraction at which we halt (e.g. 0.85). Below it we allow.
    """

    allowed: bool
    reason: str
    daily_used: float
    daily_limit: float
    rolling_used: float
    rolling_limit: float
    daily_pct: float
    rolling_pct: float
    halt_threshold: float


class UsageGovernor:
    """
    Tracks token consumption against a daily budget and a rolling-window budget,
    and decides when automated usage must HALT (reserving headroom for humans).

    Typical usage::

        gov = UsageGovernor(daily_budget=1_000_000, rolling_budget=100_000)

        # Pre-flight: will this estimated call fit under the caps?
        if gov.would_allow(est_tokens=5_000):
            ...make the LLM call...
            gov.record(tokens=actual_tokens, requests=1, cost=0.02)

        # Or just gate on current state:
        if gov.check().allowed:
            ...
    """

    def __init__(
        self,
        daily_budget: float,
        rolling_budget: float,
        rolling_window_seconds: int = 3600,
        reserve_fraction: float = 0.15,
        state_path: str = "data/usage.json",
        logger=None,
    ) -> None:
        """
        Parameters:
          daily_budget           — token cap per UTC calendar day. 0 means UNLIMITED.
          rolling_budget         — token cap over the rolling window. 0 means UNLIMITED.
          rolling_window_seconds — length of the sliding window in seconds (default 1h).
          reserve_fraction       — fraction of each budget reserved for interactive
                                   use (default 0.15). The halt threshold becomes
                                   1 - reserve_fraction (so 0.85).
          state_path             — JSON file to persist the event log to.
          logger                 — optional logger-like object (anything with
                                   .info / .warning); used for non-fatal notices.
        """
        self.daily_budget = float(daily_budget)
        self.rolling_budget = float(rolling_budget)
        self.rolling_window_seconds = int(rolling_window_seconds)
        self.reserve_fraction = float(reserve_fraction)
        # The halt threshold is the fraction of a budget at which we stop
        # automated spend. With a 15% reserve, we halt at 85%.
        self.halt_threshold = 1.0 - self.reserve_fraction
        self.state_path = state_path
        self.logger = logger

        # Backoff state for HTTP 429 ("Too Many Requests") handling.
        self.consecutive_429 = 0

        # In-memory event log. Each event is a dict: {ts, tokens, requests, cost}.
        self._events: list[dict] = self._load()

    # ----- persistence -----------------------------------------------------

    def _log(self, level: str, message: str) -> None:
        """Send a message to the logger if one was provided (otherwise stay quiet)."""
        if self.logger is None:
            return
        fn = getattr(self.logger, level, None)
        if callable(fn):
            fn(message)

    def _load(self) -> list[dict]:
        """
        Load the persisted event log from `state_path`.

        Robustness: a missing file, an empty file, invalid JSON, or an
        unexpected shape all result in starting fresh (an empty list) rather
        than raising. We never want budget bookkeeping to crash the platform.
        """
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
            return []

        # Accept either a bare list of events or a wrapper dict {"events": [...]}.
        if isinstance(data, dict):
            data = data.get("events", [])
        if not isinstance(data, list):
            self._log("warning", "usage state file had unexpected shape; starting fresh")
            return []

        # Keep only well-formed event dicts; silently drop anything weird.
        clean: list[dict] = []
        for item in data:
            if isinstance(item, dict) and "ts" in item:
                clean.append(
                    {
                        "ts": str(item.get("ts")),
                        "tokens": float(item.get("tokens", 0.0) or 0.0),
                        "requests": int(item.get("requests", 0) or 0),
                        "cost": float(item.get("cost", 0.0) or 0.0),
                    }
                )
        return clean

    def _save(self) -> None:
        """
        Persist the in-memory event log to `state_path` as JSON.

        Parent directories are created as needed. We write atomically (to a
        temporary file, then rename) so a crash mid-write cannot leave a
        half-written, corrupt file behind.
        """
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        payload = {"events": self._events}
        tmp_path = f"{self.state_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp_path, self.state_path)
        except OSError as exc:
            self._log("warning", f"could not persist usage state: {exc}")

    # ----- pruning ---------------------------------------------------------

    def _retention_cutoff(self, now: datetime) -> datetime:
        """
        Compute the earliest timestamp we still need to keep.

        We must retain enough history to answer BOTH questions:
          * "how much was used today?" -> need everything since UTC midnight.
          * "how much in the rolling window?" -> need the last `window` seconds.
        We keep whichever of those two reaches further back in time. Anything
        older than that can be pruned to bound the file size, because it can no
        longer affect any decision.
        """
        from datetime import timedelta

        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        window_start = now - timedelta(seconds=self.rolling_window_seconds)
        # The earlier (further-back) of the two boundaries is our cutoff.
        return min(midnight, window_start)

    def _prune(self, now: datetime) -> None:
        """Drop events older than the retention cutoff (in place)."""
        cutoff = self._retention_cutoff(now)
        self._events = [e for e in self._events if _parse_ts(e["ts"]) >= cutoff]

    # ----- recording -------------------------------------------------------

    def record(
        self,
        tokens: float = 0.0,
        requests: int = 1,
        cost: float = 0.0,
        now: datetime | None = None,
    ) -> None:
        """
        Record a usage event and persist the updated log.

        Parameters:
          tokens   — number of tokens consumed by this event (the budgeted unit).
          requests — number of requests this event represents (auxiliary counter).
          cost     — monetary cost of this event (auxiliary counter).
          now      — OPTIONAL explicit "current time" (UTC). For tests only; if
                     omitted the real UTC clock is used. The recorded `ts` is
                     this time in ISO-8601 form.

        After appending, we prune events that are too old to matter (older than
        both the current UTC day and the rolling window) to keep the file small.
        """
        if now is None:
            now = _utcnow()
        event = {
            "ts": now.astimezone(timezone.utc).isoformat(),
            "tokens": float(tokens),
            "requests": int(requests),
            "cost": float(cost),
        }
        self._events.append(event)
        self._prune(now)
        self._save()

    # ----- core computation ------------------------------------------------

    def _usage(self, now: datetime) -> tuple[float, float]:
        """
        Return (daily_used, rolling_used) token sums as of `now`.

        daily_used   — sum of tokens for events on the same UTC calendar day as `now`.
        rolling_used — sum of tokens for events within the last `rolling_window_seconds`.
        """
        from datetime import timedelta

        today = now.date()
        window_start = now - timedelta(seconds=self.rolling_window_seconds)

        daily_used = 0.0
        rolling_used = 0.0
        for event in self._events:
            ts = _parse_ts(event["ts"])
            tokens = float(event.get("tokens", 0.0))
            if ts.date() == today:
                daily_used += tokens
            if ts >= window_start:
                rolling_used += tokens
        return daily_used, rolling_used

    @staticmethod
    def _pct(used: float, limit: float) -> float:
        """
        Fraction of `limit` used. Returns 0.0 when limit is 0 (unlimited) so we
        never divide by zero and never report a percentage for an unlimited budget.
        """
        if limit <= 0:
            return 0.0
        return used / limit

    def _decide(
        self, daily_used: float, rolling_used: float
    ) -> UsageDecision:
        """
        Build a UsageDecision from raw used-token sums.

        A budget of 0 means UNLIMITED: that cap can never cause a halt. Otherwise
        the cap is hit once usage reaches `halt_threshold` (e.g. 85%) of the budget.
        """
        # A cap is "active" only if its budget is positive.
        daily_capped = self.daily_budget > 0
        rolling_capped = self.rolling_budget > 0

        daily_limit_hit = daily_capped and daily_used >= self.halt_threshold * self.daily_budget
        rolling_limit_hit = rolling_capped and rolling_used >= self.halt_threshold * self.rolling_budget

        allowed = not (daily_limit_hit or rolling_limit_hit)

        # Compose a clear reason. If both caps are hit we mention both.
        pct = int(round(self.halt_threshold * 100))
        if allowed:
            reason = "within budget"
        else:
            hits = []
            if daily_limit_hit:
                hits.append(
                    f"daily cap reached ({daily_used:.0f}/{self.daily_budget:.0f} "
                    f"tokens, halt at {pct}%)"
                )
            if rolling_limit_hit:
                hits.append(
                    f"rolling-window cap reached ({rolling_used:.0f}/{self.rolling_budget:.0f} "
                    f"tokens in last {self.rolling_window_seconds}s, halt at {pct}%)"
                )
            reason = "HALT: " + "; ".join(hits)

        return UsageDecision(
            allowed=allowed,
            reason=reason,
            daily_used=daily_used,
            daily_limit=self.daily_budget,
            rolling_used=rolling_used,
            rolling_limit=self.rolling_budget,
            daily_pct=self._pct(daily_used, self.daily_budget),
            rolling_pct=self._pct(rolling_used, self.rolling_budget),
            halt_threshold=self.halt_threshold,
        )

    def check(self, now: datetime | None = None) -> UsageDecision:
        """
        Evaluate current usage against both budgets and return a UsageDecision.

        `allowed` is True only when BOTH of the following hold:
            daily_used   < halt_threshold * daily_budget   (or daily budget is 0)
            rolling_used < halt_threshold * rolling_budget (or rolling budget is 0)

        Parameters:
          now — OPTIONAL explicit "current time" (UTC), for tests. Omit in normal use.
        """
        if now is None:
            now = _utcnow()
        daily_used, rolling_used = self._usage(now)
        return self._decide(daily_used, rolling_used)

    def would_allow(self, est_tokens: float, now: datetime | None = None) -> bool:
        """
        Pre-flight check: would a call of roughly `est_tokens` tokens still be
        allowed, *if* we recorded it? This lets a caller decide BEFORE spending.

        It is exactly like `check()` except the estimated tokens are added to both
        the daily and rolling sums before applying the thresholds. Nothing is
        recorded or persisted.

        Parameters:
          now — OPTIONAL explicit "current time" (UTC), for tests. Omit in normal use.
        """
        if now is None:
            now = _utcnow()
        daily_used, rolling_used = self._usage(now)
        decision = self._decide(daily_used + float(est_tokens), rolling_used + float(est_tokens))
        return decision.allowed

    # ----- HTTP 429 backoff ------------------------------------------------

    def on_rate_limit(self, retry_after: float | None = None) -> float:
        """
        Handle an HTTP 429 ("Too Many Requests") response with graceful,
        exponential backoff. Call this each time you receive a 429; it returns
        how many seconds the caller should wait before retrying.

        Behaviour:
          * We keep a counter of CONSECUTIVE 429s (incremented on every call).
          * If the server told us how long to wait via a `retry_after` value
            (e.g. the HTTP Retry-After header), we honour it verbatim.
          * Otherwise we back off exponentially: 1, 2, 4, 8, ... seconds,
            computed as 1.0 * 2**(n-1) for the n-th consecutive 429, capped at
            60 seconds so we never sleep absurdly long.

        Call `reset_backoff()` after a successful (non-429) response to clear the
        counter so the next burst starts from 1 second again.
        """
        self.consecutive_429 += 1
        if retry_after is not None:
            return float(retry_after)
        # 1, 2, 4, 8, ... capped at 60 seconds.
        delay = 1.0 * (2 ** (self.consecutive_429 - 1))
        return min(60.0, delay)

    def reset_backoff(self) -> None:
        """Reset the consecutive-429 counter (call after a successful response)."""
        self.consecutive_429 = 0

    # ----- model tiering hook ---------------------------------------------

    def tier_model(self, importance: str = "normal", now: datetime | None = None) -> str:
        """
        Recommend WHICH model tier to use for a task — a routing hint, not a hard gate.

        Idea: spend the expensive ("strong") model only when it is worth it AND we
        have comfortable budget headroom; otherwise prefer the "cheap" model to
        stretch the budget.

        Rules:
          * If we are close to a cap (daily OR rolling usage at/above 60% of its
            budget), always recommend "cheap" — conserve what's left.
          * Otherwise, if the task is important ("high" or "critical") and the
            budget is fresh (comfortable headroom), recommend "strong".
          * In all other cases recommend "cheap".

        Returns the string "strong" or "cheap".

        Parameters:
          importance — task importance label; "high"/"critical" unlock "strong".
          now        — OPTIONAL explicit "current time" (UTC), for tests.
        """
        if now is None:
            now = _utcnow()
        daily_used, rolling_used = self._usage(now)
        daily_pct = self._pct(daily_used, self.daily_budget)
        rolling_pct = self._pct(rolling_used, self.rolling_budget)

        comfortable = 0.6  # below this fraction we consider headroom "comfortable"
        # If EITHER budget is already 60%+ consumed, conserve with the cheap model.
        if daily_pct >= comfortable or rolling_pct >= comfortable:
            return "cheap"

        if importance in {"high", "critical"}:
            return "strong"
        return "cheap"

    # ----- dashboard snapshot ---------------------------------------------

    def snapshot(self, now: datetime | None = None) -> dict:
        """
        Return a plain dict suitable for driving a dashboard "fuel gauge".

        Keys:
          daily_used, daily_limit, daily_pct,
          rolling_used, rolling_limit, rolling_pct,
          halt_threshold, halted (bool), reason, consecutive_429.

        Parameters:
          now — OPTIONAL explicit "current time" (UTC), for tests.
        """
        if now is None:
            now = _utcnow()
        decision = self.check(now=now)
        return {
            "daily_used": decision.daily_used,
            "daily_limit": decision.daily_limit,
            "daily_pct": decision.daily_pct,
            "rolling_used": decision.rolling_used,
            "rolling_limit": decision.rolling_limit,
            "rolling_pct": decision.rolling_pct,
            "halt_threshold": decision.halt_threshold,
            "halted": not decision.allowed,
            "reason": decision.reason,
            "consecutive_429": self.consecutive_429,
        }
