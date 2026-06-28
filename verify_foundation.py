"""End-to-end verification of the goldbot foundation.

Run this to confirm the data layer works from a clean slate:

    python verify_foundation.py

It will:
  1. Initialize the database and create all tables.
  2. Seed all 10 accounts from goldbot.config.
  3. Write one dummy trade to account 1, read it back, and print it.
  4. Log an account-state transition for account 1.
  5. Print all 10 accounts with their starting equity.

By default it uses a throwaway file `verify_foundation.db` and deletes it first,
so each run is reproducible. Nothing here touches real money or a broker — it is
pure simulation plumbing.
"""

import os
from datetime import datetime, timezone

from goldbot import Database, ACCOUNTS


DB_PATH = "verify_foundation.db"


def iso_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    # Start from a clean slate so the verification is reproducible.
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    with Database(DB_PATH) as db:
        # 1. Initialize the database and all tables.
        db.initialize()
        print("1. Database initialized and tables created.")

        # 2. Create all 10 accounts from config.
        created = db.seed_accounts(ACCOUNTS)
        print(f"2. Seeded {created} accounts from config.\n")

        # 3. Write one dummy trade to account 1.
        #    Realistic-looking XAU/USD numbers, but entirely fabricated.
        now = iso_now()
        entry_price = 2350.00
        dummy_trade = {
            "account_id": 1,
            "strategy_name": ACCOUNTS[0].strategy_name,  # ma_crossover
            "signal_time": now,
            "entry_time": now,
            "exit_time": now,
            "direction": "long",
            "signal_price": 2349.50,
            "entry_price": entry_price,
            "exit_price": 2359.40,
            "spread_at_entry": 0.30,
            "stop_loss_price": entry_price * (1 - 0.0025),   # sl_pct = 0.25%
            "take_profit_price": entry_price * (1 + 0.0040), # tp_pct = 0.40%
            "lot_size": 0.01,
            "exit_reason": "tp_hit",
            "pnl_gross": 9.90,
            "pnl_net": 9.60,
            "outcome": "win",
            "running_streak": 0,        # a win resets the loss streak
            "streak_trigger_count": 0,
            "longest_streak_so_far": 0,
            "concurrent_at_entry": 1,
            "trades_to_target": 1,      # first completed trade toward 1000
            "time_elapsed_seconds": 42,
            "data_fresh_at_entry": 1,   # feed was fresh
            "account_equity_after": ACCOUNTS[0].starting_balance + 9.60,
        }
        trade_id = db.write_trade(dummy_trade)
        print(f"3. Wrote dummy trade to account 1 (trade_id={trade_id}). Reading it back:\n")

        # Read it back and print every field.
        trades = db.get_trades(1)
        assert len(trades) == 1, "expected exactly one trade for account 1"
        for key in trades[0].keys():
            print(f"     {key:<22} = {trades[0][key]}")
        print()

        # 4. Log an account-state transition for account 1.
        equity_now = db.get_equity(1)
        state_id = db.log_state(
            account_id=1,
            timestamp=iso_now(),
            state="running",
            equity=equity_now,
            note="Account started and first trade recorded.",
        )
        latest = db.get_latest_state(1)
        print(f"4. Logged state transition (id={state_id}):")
        print(
            f"     account 1 -> state='{latest['state']}', "
            f"equity={latest['equity']}, note='{latest['note']}'\n"
        )

        # 5. Print all 10 accounts with their starting equity.
        print("5. All 10 accounts (current equity; account 1 reflects the dummy trade):")
        print(f"     {'id':>3}  {'strategy':<28} {'start_balance':>13}  {'current_equity':>14}")
        print(f"     {'-'*3}  {'-'*28} {'-'*13}  {'-'*14}")
        for account in db.get_all_accounts():
            equity = db.get_equity(account["account_id"])
            print(
                f"     {account['account_id']:>3}  "
                f"{account['strategy_name']:<28} "
                f"{account['starting_balance']:>13,.2f}  "
                f"{equity:>14,.2f}"
            )

        print("\nFoundation verified end to end.")


if __name__ == "__main__":
    main()
