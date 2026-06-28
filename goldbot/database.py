"""Data-access layer for the shadow-trading foundation.

A thin, fully-parameterized wrapper around a single SQLite database file.
Every query uses `?` placeholders — values are never interpolated into SQL
strings — so the layer is injection-safe by construction.

Public surface (the things the rest of the bot will call):

    db = Database("goldbot.db")
    db.initialize()                       # create the DB file + all tables
    db.seed_accounts()                    # insert all 10 accounts from config
    db.create_account(account_config)     # insert a single account
    db.write_trade({...})                 # record one completed trade
    db.write_dropped_signal(...)          # record a skipped signal
    db.log_state(...)                     # record an account-state transition
    db.get_trades(account_id)             # all trades for an account
    db.get_equity(account_id)             # current equity
    db.get_latest_state(account_id)       # latest logged state row
    db.get_account(account_id)            # static config row

The Database can be used as a context manager:

    with Database("goldbot.db") as db:
        db.initialize()
        ...
"""

import sqlite3
from typing import Dict, Iterable, List, Optional

from . import schema
from .config import ACCOUNTS, AccountConfig


# The exact set of writable columns on `trades` (trade_id is auto-assigned).
# Used to validate caller-supplied trade dicts before building the INSERT.
_TRADE_COLUMNS = [
    "account_id",
    "strategy_name",
    "signal_time",
    "entry_time",
    "exit_time",
    "direction",
    "signal_price",
    "entry_price",
    "exit_price",
    "spread_at_entry",
    "stop_loss_price",
    "take_profit_price",
    "lot_size",
    "exit_reason",
    "pnl_gross",
    "pnl_net",
    "outcome",
    "running_streak",
    "streak_trigger_count",
    "longest_streak_so_far",
    "concurrent_at_entry",
    "trades_to_target",
    "time_elapsed_seconds",
    "data_fresh_at_entry",
    "account_equity_after",
]


class Database:
    """Connection + data-access methods for the shadow-trading database."""

    def __init__(self, path: str = "goldbot.db"):
        """Open (or create) the SQLite database at `path`.

        `path` may be ":memory:" for an ephemeral in-memory database, which is
        convenient for tests.
        """
        self.path = path
        # check_same_thread=False keeps things simple for later multi-account
        # workers; access should still be serialized by the caller.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        # Return rows as sqlite3.Row so callers can use column names.
        self._conn.row_factory = sqlite3.Row
        # Enforce the FOREIGN KEY relationships declared in the schema.
        self._conn.execute("PRAGMA foreign_keys = ON;")

    # -- lifecycle -----------------------------------------------------------

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    # -- schema --------------------------------------------------------------

    def initialize(self) -> None:
        """Create all tables and indexes if they do not already exist.

        Safe to call repeatedly — every statement uses IF NOT EXISTS.
        """
        with self._conn:  # implicit transaction: commit on success
            for statement in schema.ALL_STATEMENTS:
                self._conn.executescript(statement)

    # -- accounts ------------------------------------------------------------

    def create_account(self, account: AccountConfig) -> None:
        """Insert (or replace) a single account's static configuration."""
        sql = """
            INSERT OR REPLACE INTO accounts (
                account_id, strategy_name, starting_balance, lot_size,
                tp_pct, sl_pct, max_concurrent, trade_count_target,
                hard_limit_pct, streak_threshold
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            account.account_id,
            account.strategy_name,
            account.starting_balance,
            account.lot_size,
            account.tp_pct,
            account.sl_pct,
            account.max_concurrent,
            account.trade_count_target,
            account.hard_limit_pct,
            account.streak_threshold,
        )
        with self._conn:
            self._conn.execute(sql, params)

    def seed_accounts(self, accounts: Iterable[AccountConfig] = ACCOUNTS) -> int:
        """Create all accounts from config (defaults to the 10 in goldbot.config).

        Returns the number of accounts written.
        """
        count = 0
        for account in accounts:
            self.create_account(account)
            count += 1
        return count

    def get_account(self, account_id: int) -> Optional[sqlite3.Row]:
        """Return the static config row for an account, or None if absent."""
        cur = self._conn.execute(
            "SELECT * FROM accounts WHERE account_id = ?;", (account_id,)
        )
        return cur.fetchone()

    def get_all_accounts(self) -> List[sqlite3.Row]:
        """Return every account's static config row, ordered by account_id."""
        cur = self._conn.execute("SELECT * FROM accounts ORDER BY account_id;")
        return cur.fetchall()

    # -- trades --------------------------------------------------------------

    def write_trade(self, trade: Dict) -> int:
        """Insert one completed trade.

        `trade` is a dict keyed by column name (see _TRADE_COLUMNS). Missing
        columns are stored as NULL; unknown keys raise ValueError so typos are
        caught early rather than silently dropped.

        Returns the auto-assigned trade_id.
        """
        unknown = set(trade) - set(_TRADE_COLUMNS)
        if unknown:
            raise ValueError(f"Unknown trade column(s): {sorted(unknown)}")

        # Insert only the columns the caller supplied; the rest default to NULL.
        columns = [c for c in _TRADE_COLUMNS if c in trade]
        placeholders = ", ".join("?" for _ in columns)
        column_list = ", ".join(columns)
        params = tuple(trade[c] for c in columns)

        sql = f"INSERT INTO trades ({column_list}) VALUES ({placeholders});"
        with self._conn:
            cur = self._conn.execute(sql, params)
        return cur.lastrowid

    def get_trades(self, account_id: int) -> List[sqlite3.Row]:
        """Return all trades for an account, oldest first (by trade_id)."""
        cur = self._conn.execute(
            "SELECT * FROM trades WHERE account_id = ? ORDER BY trade_id;",
            (account_id,),
        )
        return cur.fetchall()

    # -- dropped signals -----------------------------------------------------

    def write_dropped_signal(
        self,
        account_id: int,
        strategy_name: str,
        signal_time: str,
        direction: str,
        reason: str = "max_concurrent_full",
    ) -> int:
        """Record a signal that was skipped (e.g. concurrency was full).

        Returns the auto-assigned id.
        """
        sql = """
            INSERT INTO dropped_signals (
                account_id, strategy_name, signal_time, direction, reason
            ) VALUES (?, ?, ?, ?, ?);
        """
        params = (account_id, strategy_name, signal_time, direction, reason)
        with self._conn:
            cur = self._conn.execute(sql, params)
        return cur.lastrowid

    def get_dropped_signals(self, account_id: int) -> List[sqlite3.Row]:
        """Return all dropped signals for an account, oldest first."""
        cur = self._conn.execute(
            "SELECT * FROM dropped_signals WHERE account_id = ? ORDER BY id;",
            (account_id,),
        )
        return cur.fetchall()

    # -- account state log ---------------------------------------------------

    def log_state(
        self,
        account_id: int,
        timestamp: str,
        state: str,
        equity: float,
        note: str = "",
    ) -> int:
        """Record an account-state transition.

        `state` is one of: 'running', 'manually_paused', 'stale_paused', 'closed'.
        Returns the auto-assigned id.
        """
        sql = """
            INSERT INTO account_state_log (
                account_id, timestamp, state, equity, note
            ) VALUES (?, ?, ?, ?, ?);
        """
        params = (account_id, timestamp, state, equity, note)
        with self._conn:
            cur = self._conn.execute(sql, params)
        return cur.lastrowid

    def get_latest_state(self, account_id: int) -> Optional[sqlite3.Row]:
        """Return the most recent state-log row for an account, or None.

        Ordered by id so the latest insert wins even if two rows share a
        timestamp.
        """
        cur = self._conn.execute(
            """
            SELECT * FROM account_state_log
            WHERE account_id = ?
            ORDER BY id DESC
            LIMIT 1;
            """,
            (account_id,),
        )
        return cur.fetchone()

    # -- derived reads -------------------------------------------------------

    def get_equity(self, account_id: int) -> Optional[float]:
        """Return the account's current equity.

        Current equity is the `account_equity_after` of the most recent trade.
        If no trades have completed yet, fall back to the account's
        starting_balance. Returns None if the account does not exist.
        """
        cur = self._conn.execute(
            """
            SELECT account_equity_after
            FROM trades
            WHERE account_id = ?
            ORDER BY trade_id DESC
            LIMIT 1;
            """,
            (account_id,),
        )
        row = cur.fetchone()
        if row is not None and row["account_equity_after"] is not None:
            return row["account_equity_after"]

        # No trades yet — fall back to the configured starting balance.
        account = self.get_account(account_id)
        if account is None:
            return None
        return account["starting_balance"]
