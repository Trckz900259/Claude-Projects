"""SQLite schema (DDL) for the shadow-trading foundation.

Three tables:
  * trades             — one row per completed trade
  * dropped_signals    — signals skipped because max concurrency was full
  * account_state_log  — timestamped account state transitions

An additional `accounts` table holds the static per-account configuration so the
database is self-describing (you can read the parameters a trade ran under
without consulting the config module). It is seeded from goldbot.config.

The field lists below match the requested spec exactly. Timestamps are stored as
ISO-8601 TEXT. SQLite has no native BOOLEAN, so 0/1 INTEGER flags are used.
"""

# Static per-account configuration, seeded from goldbot.config.ACCOUNTS.
CREATE_ACCOUNTS = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id          INTEGER PRIMARY KEY,
    strategy_name       TEXT    NOT NULL,
    starting_balance    REAL    NOT NULL,
    lot_size            REAL    NOT NULL,
    tp_pct              REAL    NOT NULL,
    sl_pct              REAL    NOT NULL,
    max_concurrent      INTEGER NOT NULL,
    trade_count_target  INTEGER NOT NULL,
    hard_limit_pct      REAL    NOT NULL,
    streak_threshold    INTEGER NOT NULL
);
"""

# One row per completed trade.
CREATE_TRADES = """
CREATE TABLE IF NOT EXISTS trades (
    trade_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id            INTEGER NOT NULL,
    strategy_name         TEXT    NOT NULL,

    signal_time           TEXT,
    entry_time            TEXT,
    exit_time             TEXT,

    direction             TEXT,              -- 'long' | 'short'

    signal_price          REAL,
    entry_price           REAL,
    exit_price            REAL,
    spread_at_entry       REAL,
    stop_loss_price       REAL,
    take_profit_price     REAL,

    lot_size              REAL,
    exit_reason           TEXT,              -- 'tp_hit' | 'sl_hit' | 'data_stale' | 'account_closed'

    pnl_gross             REAL,
    pnl_net               REAL,
    outcome               TEXT,              -- 'win' | 'loss'

    running_streak        INTEGER,           -- consecutive losses at this trade, 0 on a win
    streak_trigger_count  INTEGER,           -- cumulative times the 5-loss threshold has tripped
    longest_streak_so_far INTEGER,
    concurrent_at_entry   INTEGER,           -- open positions when this one opened
    trades_to_target      INTEGER,           -- running completed-trade count toward 1000
    time_elapsed_seconds  INTEGER,           -- wall-clock since this account started
    data_fresh_at_entry   INTEGER,           -- 0/1 was the price feed fresh at open
    account_equity_after  REAL,              -- running account balance after this trade

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);
"""

# Signals skipped because the account was already at max concurrency.
CREATE_DROPPED_SIGNALS = """
CREATE TABLE IF NOT EXISTS dropped_signals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id    INTEGER NOT NULL,
    strategy_name TEXT,
    signal_time   TEXT,
    direction     TEXT,
    reason        TEXT,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);
"""

# Timestamped account state transitions.
CREATE_ACCOUNT_STATE_LOG = """
CREATE TABLE IF NOT EXISTS account_state_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    timestamp  TEXT,
    state      TEXT,                          -- 'running' | 'manually_paused' | 'stale_paused' | 'closed'
    equity     REAL,
    note       TEXT,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);
"""

# Helpful indexes for the common access pattern (everything is queried by account).
CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_trades_account            ON trades (account_id);
CREATE INDEX IF NOT EXISTS idx_dropped_account           ON dropped_signals (account_id);
CREATE INDEX IF NOT EXISTS idx_state_log_account         ON account_state_log (account_id);
CREATE INDEX IF NOT EXISTS idx_state_log_account_time    ON account_state_log (account_id, timestamp);
"""

# Executed in order by Database.initialize().
ALL_STATEMENTS = [
    CREATE_ACCOUNTS,
    CREATE_TRADES,
    CREATE_DROPPED_SIGNALS,
    CREATE_ACCOUNT_STATE_LOG,
    CREATE_INDEXES,
]
