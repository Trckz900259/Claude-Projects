"""
Tests for the Usage Governor (core/usage.py).

These tests use the optional `now: datetime` parameter that
record()/check()/would_allow()/tier_model()/snapshot() accept. Passing an
explicit UTC "current time" lets us simulate the passage of time deterministically
(no real sleeping required): we record events at an old `now`, then evaluate at a
later `now` to prove the rolling window slides and usage "ages out".

Each test points the governor at a fresh temp state file via pytest's `tmp_path`,
so tests never touch the real `data/usage.json` and never interfere with each other.
"""

from datetime import datetime, timedelta, timezone

from core.usage import UsageGovernor, UsageDecision


def _gov(tmp_path, **kwargs):
    """Build a governor whose state file lives inside the test's temp dir."""
    state_path = str(tmp_path / "usage.json")
    kwargs.setdefault("daily_budget", 1000.0)
    kwargs.setdefault("rolling_budget", 1000.0)
    return UsageGovernor(state_path=state_path, **kwargs)


# A fixed reference "now" so every test is fully deterministic. Mid-day UTC so
# that subtracting a rolling window stays within the same calendar day.
NOW = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)


# --- (1) daily cap: under 85% allowed, crossing 85% halts ------------------

def test_daily_under_threshold_is_allowed(tmp_path):
    # Huge rolling budget so only the daily cap can matter here.
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=10_000_000.0)
    # 840 of 1000 = 84% < 85% -> still allowed.
    gov.record(tokens=840.0, now=NOW)

    decision = gov.check(now=NOW)
    assert isinstance(decision, UsageDecision)
    assert decision.allowed is True
    assert decision.daily_used == 840.0
    assert decision.daily_pct == 0.84
    assert decision.halt_threshold == 0.85


def test_daily_crossing_threshold_halts_with_daily_reason(tmp_path):
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=10_000_000.0)
    # 850 of 1000 = exactly 85% -> halt (>= threshold).
    gov.record(tokens=860.0, now=NOW)

    decision = gov.check(now=NOW)
    assert decision.allowed is False
    assert "daily" in decision.reason.lower()
    assert decision.daily_used == 860.0


def test_would_allow_preflight_blocks_before_recording(tmp_path):
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=10_000_000.0)
    gov.record(tokens=800.0, now=NOW)  # 80% used so far

    # Adding 40 more -> 840 (84%) still fits.
    assert gov.would_allow(40.0, now=NOW) is True
    # Adding 100 more -> 900 (90%) would cross the halt line.
    assert gov.would_allow(100.0, now=NOW) is False
    # would_allow must not have recorded anything.
    assert gov.check(now=NOW).daily_used == 800.0


# --- (2) rolling cap halts independently, then RESUMES as time passes ------

def test_rolling_cap_halts_independently_then_resumes(tmp_path):
    # Daily budget effectively unlimited (huge) so ONLY the rolling cap bites.
    # 10-minute window keeps the math easy.
    gov = _gov(
        tmp_path,
        daily_budget=10_000_000.0,
        rolling_budget=1000.0,
        rolling_window_seconds=600,
    )

    # Spend 900 tokens "now" -> 90% of the rolling budget -> HALT.
    gov.record(tokens=900.0, now=NOW)
    halted = gov.check(now=NOW)
    assert halted.allowed is False
    assert "rolling" in halted.reason.lower()
    assert halted.rolling_used == 900.0
    # The daily side is far under its (huge) budget, confirming independence.
    assert halted.daily_pct < 0.85

    # Now let time pass beyond the 10-minute window. The old event ages out of
    # the rolling window, so rolling_used drops back to 0 and we RESUME.
    later = NOW + timedelta(seconds=601)
    resumed = gov.check(now=later)
    assert resumed.rolling_used == 0.0
    assert resumed.allowed is True


# --- (3) on_rate_limit backoff increases and respects retry_after ----------

def test_on_rate_limit_exponential_backoff_increases(tmp_path):
    gov = _gov(tmp_path)
    # Consecutive 429s: 1, 2, 4, 8 seconds (1.0 * 2**(n-1)).
    assert gov.on_rate_limit() == 1.0
    assert gov.on_rate_limit() == 2.0
    assert gov.on_rate_limit() == 4.0
    assert gov.on_rate_limit() == 8.0
    assert gov.consecutive_429 == 4

    # reset_backoff clears the counter so it starts from 1 again.
    gov.reset_backoff()
    assert gov.consecutive_429 == 0
    assert gov.on_rate_limit() == 1.0


def test_on_rate_limit_respects_explicit_retry_after(tmp_path):
    gov = _gov(tmp_path)
    # An explicit server-provided wait is honoured verbatim.
    assert gov.on_rate_limit(retry_after=12.5) == 12.5


def test_on_rate_limit_is_capped_at_60(tmp_path):
    gov = _gov(tmp_path)
    # Many consecutive 429s -> 2**(n-1) explodes, but the result is capped at 60.
    for _ in range(20):
        delay = gov.on_rate_limit()
    assert delay == 60.0


# --- (4) tier_model: "strong" when fresh+important, "cheap" near the cap ----

def test_tier_model_strong_when_fresh_and_high_importance(tmp_path):
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=1000.0)
    # No usage recorded -> budget is fresh -> important task gets the strong model.
    assert gov.tier_model("high", now=NOW) == "strong"
    assert gov.tier_model("critical", now=NOW) == "strong"
    # A normal-importance task does not warrant the strong model even when fresh.
    assert gov.tier_model("normal", now=NOW) == "cheap"


def test_tier_model_cheap_near_the_cap(tmp_path):
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=1000.0)
    # 700/1000 = 70% used -> >= 60% headroom threshold -> conserve with "cheap"
    # even for a critical task.
    gov.record(tokens=700.0, now=NOW)
    assert gov.tier_model("critical", now=NOW) == "cheap"
    assert gov.tier_model("high", now=NOW) == "cheap"


# --- (5) budget 0 means UNLIMITED (never halts, no divide-by-zero) ----------

def test_zero_budget_is_unlimited(tmp_path):
    gov = _gov(tmp_path, daily_budget=0.0, rolling_budget=0.0)
    # Record an enormous amount of usage.
    gov.record(tokens=10_000_000.0, now=NOW)

    decision = gov.check(now=NOW)
    assert decision.allowed is True            # never halts
    assert decision.daily_pct == 0.0           # no divide-by-zero; reported as 0
    assert decision.rolling_pct == 0.0
    # Pre-flight with a giant estimate is still allowed under unlimited budgets.
    assert gov.would_allow(10_000_000.0, now=NOW) is True


# --- bonus: persistence + snapshot sanity ----------------------------------

def test_state_persists_across_instances(tmp_path):
    state_path = str(tmp_path / "usage.json")
    gov1 = UsageGovernor(
        daily_budget=1000.0, rolling_budget=1000.0, state_path=state_path
    )
    gov1.record(tokens=500.0, requests=3, cost=0.05, now=NOW)

    # A brand-new instance pointed at the same file should see the prior event.
    gov2 = UsageGovernor(
        daily_budget=1000.0, rolling_budget=1000.0, state_path=state_path
    )
    assert gov2.check(now=NOW).daily_used == 500.0


def test_corrupt_state_file_starts_fresh(tmp_path):
    state_path = tmp_path / "usage.json"
    state_path.write_text("{ this is not valid json", encoding="utf-8")
    # Loading a corrupt file must not raise; it just starts empty.
    gov = UsageGovernor(
        daily_budget=1000.0, rolling_budget=1000.0, state_path=str(state_path)
    )
    assert gov.check(now=NOW).daily_used == 0.0


def test_snapshot_shape(tmp_path):
    gov = _gov(tmp_path, daily_budget=1000.0, rolling_budget=1000.0)
    gov.record(tokens=900.0, now=NOW)
    gov.on_rate_limit()  # bump the 429 counter so we can see it surface

    snap = gov.snapshot(now=NOW)
    expected_keys = {
        "daily_used", "daily_limit", "daily_pct",
        "rolling_used", "rolling_limit", "rolling_pct",
        "halt_threshold", "halted", "reason", "consecutive_429",
    }
    assert set(snap.keys()) == expected_keys
    assert snap["halted"] is True          # 90% used -> halted
    assert snap["consecutive_429"] == 1
