"""goldbot — foundation and data layer for the XAU/USD shadow-trading bot.

This package is the foundation everything else writes to. It currently
contains only:

  * config   — the 10 simulated account definitions and shared parameters
  * schema   — the SQLite table definitions (DDL)
  * database — the data-access layer (a thin, parameterized wrapper around SQLite)

No strategies, price feeds, or execution logic live here yet — by design.
"""

from .config import ACCOUNTS, ACCOUNT_DEFAULTS, STRATEGY_NAMES, AccountConfig
from .database import Database

__all__ = [
    "ACCOUNTS",
    "ACCOUNT_DEFAULTS",
    "STRATEGY_NAMES",
    "AccountConfig",
    "Database",
]

__version__ = "0.1.0"
