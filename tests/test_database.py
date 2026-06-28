"""Tests for the goldbot data-access layer.

Each test runs against a fresh in-memory database (see conftest.py), so tests
are isolated and fast. Together they cover schema creation, account seeding,
trade round-tripping, validation, equity derivation, dropped signals, and the
state log.
"""

import pytest

from goldbot import ACCOUNTS, ACCOUNT_DEFAULTS, Database
from goldbot.database import _TRADE_COLUMNS


# A fully-populated trade dict used by several tests. Realistic-looking but
# fabricated XAU/USD numbers.
def make_full_trade(account_id=1, strategy_name="ma_crossover", **overrides):
    trade = {
        "account_id": account_id,
        "strategy_name": strategy_name,
        "signal_time": "2026-06-28T12:00:00+00:00",
        "entry_time": "2026-06-28T12:00:05+00:00",
        "exit_time": "2026-06-28T12:30:00+00:00",
        "direction": "long",
        "signal_price": 2349.50,
        "entry_price": 2350.00,
        "exit_price": 2359.40,
        "spread_at_entry": 0.30,
        "stop_loss_price": 2344.125,
        "take_profit_price": 2359.40,
        "lot_size": 0.01,
        "exit_reason": "tp_hit",
        "pnl_gross": 9.90,
        "pnl_net": 9.60,
        "outcome": "win",
        "running_streak": 0,
        "streak_trigger_count": 0,
        "longest_streak_so_far": 0,
        "concurrent_at_entry": 1,
        "trades_to_target": 1,
        "time_elapsed_seconds": 42,
        "data_fresh_at_entry": 1,
        "account_equity_after": 10009.60,
    }
    trade.update(overrides)
    return trade


# -- schema --------------------------------------------------------------------

def test_initialize_creates_all_tables(db):
    """All four tables exist after initialize()."""
    rows = db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table';"
    ).fetchall()
    names = {row["name"] for row in rows}
    assert {"accounts", "trades", "dropped_signals", "account_state_log"} <= names


def test_trades_table_has_expected_columns(db):
    """The trades table exposes exactly the spec's columns (plus trade_id PK)."""
    cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(trades);")]
    expected = ["trade_id"] + _TRADE_COLUMNS
    assert cols == expected


def test_dropped_signals_table_columns(db):
    cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(dropped_signals);")]
    assert cols == ["id", "account_id", "strategy_name", "signal_time", "direction", "reason"]


def test_account_state_log_table_columns(db):
    cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(account_state_log);")]
    assert cols == ["id", "account_id", "timestamp", "state", "equity", "note"]


def test_initialize_is_idempotent(db):
    """Calling initialize() twice does not error or duplicate tables."""
    db.initialize()  # second call (fixture already called it once)
    rows = db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='trades';"
    ).fetchall()
    assert len(rows) == 1


# -- account seeding -----------------------------------------------------------

def test_seed_creates_ten_accounts(seeded_db):
    accounts = seeded_db.get_all_accounts()
    assert len(accounts) == 10


def test_seed_strategy_names_in_order(seeded_db):
    """Accounts 1..10 carry the expected strategy names in order."""
    accounts = seeded_db.get_all_accounts()
    expected = [
        "ma_crossover", "ma_pullback", "rsi_reversion", "bollinger_reversion",
        "bollinger_squeeze_breakout", "donchian_breakout", "macd_cross",
        "stochastic", "opening_range_breakout", "vwap",
    ]
    assert [a["account_id"] for a in accounts] == list(range(1, 11))
    assert [a["strategy_name"] for a in accounts] == expected


def test_seed_applies_shared_defaults(seeded_db):
    """Every account carries the shared default parameters."""
    for account in seeded_db.get_all_accounts():
        assert account["starting_balance"] == ACCOUNT_DEFAULTS["starting_balance"]
        assert account["lot_size"] == ACCOUNT_DEFAULTS["lot_size"]
        assert account["tp_pct"] == ACCOUNT_DEFAULTS["tp_pct"]
        assert account["sl_pct"] == ACCOUNT_DEFAULTS["sl_pct"]
        assert account["max_concurrent"] == ACCOUNT_DEFAULTS["max_concurrent"]
        assert account["trade_count_target"] == ACCOUNT_DEFAULTS["trade_count_target"]
        assert account["hard_limit_pct"] == ACCOUNT_DEFAULTS["hard_limit_pct"]
        assert account["streak_threshold"] == ACCOUNT_DEFAULTS["streak_threshold"]


def test_seed_returns_count(db):
    assert db.seed_accounts() == 10


# -- write_trade round-trip ----------------------------------------------------

def test_write_trade_round_trips_all_fields(seeded_db):
    """Every field written reads back equal."""
    trade = make_full_trade()
    trade_id = seeded_db.write_trade(trade)
    assert trade_id == 1

    rows = seeded_db.get_trades(1)
    assert len(rows) == 1
    row = rows[0]
    for key, value in trade.items():
        assert row[key] == value, f"mismatch on {key}: {row[key]!r} != {value!r}"


def test_write_trade_returns_incrementing_ids(seeded_db):
    id1 = seeded_db.write_trade(make_full_trade())
    id2 = seeded_db.write_trade(make_full_trade())
    assert (id1, id2) == (1, 2)


# -- write_trade validation ----------------------------------------------------

def test_write_trade_rejects_unknown_key(seeded_db):
    bad = make_full_trade()
    bad["not_a_column"] = 123
    with pytest.raises(ValueError) as exc:
        seeded_db.write_trade(bad)
    assert "not_a_column" in str(exc.value)


def test_write_trade_stores_null_for_missing_field(seeded_db):
    """A valid-but-omitted column is stored as NULL, not a default value."""
    trade = make_full_trade()
    del trade["exit_reason"]  # valid column, intentionally omitted
    seeded_db.write_trade(trade)

    row = seeded_db.get_trades(1)[0]
    assert row["exit_reason"] is None
    # Other supplied fields are unaffected.
    assert row["outcome"] == "win"


# -- get_equity ----------------------------------------------------------------

def test_get_equity_falls_back_to_starting_balance(seeded_db):
    """With no trades, equity is the configured starting balance."""
    assert seeded_db.get_equity(1) == ACCOUNT_DEFAULTS["starting_balance"]


def test_get_equity_uses_latest_trade(seeded_db):
    """With trades, equity is the most recent trade's account_equity_after."""
    seeded_db.write_trade(make_full_trade(account_equity_after=10009.60))
    seeded_db.write_trade(make_full_trade(account_equity_after=10025.00))
    assert seeded_db.get_equity(1) == 10025.00


def test_get_equity_unknown_account_returns_none(seeded_db):
    assert seeded_db.get_equity(999) is None


# -- dropped signals -----------------------------------------------------------

def test_dropped_signal_round_trips(seeded_db):
    seeded_db.write_dropped_signal(
        account_id=2,
        strategy_name="ma_pullback",
        signal_time="2026-06-28T12:00:00+00:00",
        direction="short",
        reason="max_concurrent_full",
    )
    rows = seeded_db.get_dropped_signals(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["account_id"] == 2
    assert row["strategy_name"] == "ma_pullback"
    assert row["signal_time"] == "2026-06-28T12:00:00+00:00"
    assert row["direction"] == "short"
    assert row["reason"] == "max_concurrent_full"


def test_dropped_signals_empty_for_account_without_any(seeded_db):
    assert seeded_db.get_dropped_signals(3) == []


# -- state log -----------------------------------------------------------------

def test_log_state_and_get_latest(seeded_db):
    seeded_db.log_state(1, "2026-06-28T12:00:00+00:00", "running", 10000.0, "started")
    latest = seeded_db.get_latest_state(1)
    assert latest["state"] == "running"
    assert latest["equity"] == 10000.0
    assert latest["note"] == "started"


def test_get_latest_state_returns_most_recent(seeded_db):
    """The newest insert wins, even when timestamps are identical."""
    ts = "2026-06-28T12:00:00+00:00"
    seeded_db.log_state(1, ts, "running", 10000.0, "first")
    seeded_db.log_state(1, ts, "stale_paused", 9990.0, "feed went stale")
    latest = seeded_db.get_latest_state(1)
    assert latest["state"] == "stale_paused"
    assert latest["note"] == "feed went stale"


def test_get_latest_state_none_when_no_log(seeded_db):
    assert seeded_db.get_latest_state(1) is None


# -- get_trades ordering / emptiness ------------------------------------------

def test_get_trades_returns_in_insertion_order(seeded_db):
    """Trades come back oldest-first, by trade_id."""
    seeded_db.write_trade(make_full_trade(time_elapsed_seconds=10))
    seeded_db.write_trade(make_full_trade(time_elapsed_seconds=20))
    seeded_db.write_trade(make_full_trade(time_elapsed_seconds=30))
    rows = seeded_db.get_trades(1)
    assert [r["trade_id"] for r in rows] == [1, 2, 3]
    assert [r["time_elapsed_seconds"] for r in rows] == [10, 20, 30]


def test_get_trades_empty_for_account_without_trades(seeded_db):
    assert seeded_db.get_trades(5) == []


def test_get_trades_isolates_by_account(seeded_db):
    """A query for one account does not return another account's trades."""
    seeded_db.write_trade(make_full_trade(account_id=1))
    seeded_db.write_trade(make_full_trade(account_id=2, strategy_name="ma_pullback"))
    assert len(seeded_db.get_trades(1)) == 1
    assert len(seeded_db.get_trades(2)) == 1
    assert seeded_db.get_trades(1)[0]["account_id"] == 1
