"""Account configuration for the 10 parallel shadow-trading accounts.

Every account runs one mechanical strategy on its own simulated GBP 10,000
account. The 10 accounts are identical in every parameter except the strategy
they run, so that performance differences can be attributed to the strategy
alone (identical conditions, identical risk settings).

This module is the single source of truth for account parameters. Strategies,
feeds, and execution code (built later) must read from here rather than
hardcoding values.
"""

from dataclasses import dataclass, asdict
from typing import Dict, List


# The 10 strategy names, one per account, in account_id order (1..10).
STRATEGY_NAMES: List[str] = [
    "ma_crossover",
    "ma_pullback",
    "rsi_reversion",
    "bollinger_reversion",
    "bollinger_squeeze_breakout",
    "donchian_breakout",
    "macd_cross",
    "stochastic",
    "opening_range_breakout",
    "vwap",
]


# Shared parameters — identical across all 10 accounts.
# Kept in one place so a single edit re-tunes every account consistently.
ACCOUNT_DEFAULTS: Dict[str, float] = {
    "starting_balance": 10000.0,   # GBP, simulated capital
    "lot_size": 0.01,              # fixed position size per trade
    "tp_pct": 0.4,                 # take-profit distance, percent of entry price
    "sl_pct": 0.25,                # stop-loss distance, percent of entry price
    "max_concurrent": 10,          # max simultaneously open positions per account
    "trade_count_target": 1000,    # completed-trade target per account
    "hard_limit_pct": 25,          # drawdown hard limit, percent of starting balance
    "streak_threshold": 5,         # consecutive losses that trip the streak trigger
}


@dataclass(frozen=True)
class AccountConfig:
    """Immutable configuration for a single simulated account."""

    account_id: int
    strategy_name: str
    starting_balance: float
    lot_size: float
    tp_pct: float
    sl_pct: float
    max_concurrent: int
    trade_count_target: int
    hard_limit_pct: float
    streak_threshold: int

    def as_dict(self) -> Dict:
        """Return a plain dict (handy for DB inserts and logging)."""
        return asdict(self)


def _build_accounts() -> List[AccountConfig]:
    """Construct the 10 AccountConfig objects from the shared defaults."""
    accounts = []
    for index, strategy_name in enumerate(STRATEGY_NAMES, start=1):
        accounts.append(
            AccountConfig(
                account_id=index,
                strategy_name=strategy_name,
                **ACCOUNT_DEFAULTS,
            )
        )
    return accounts


# The canonical list of all 10 accounts, account_id 1..10.
ACCOUNTS: List[AccountConfig] = _build_accounts()
