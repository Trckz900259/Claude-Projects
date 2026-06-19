"""
audit.py — tamper-evident chain-of-custody audit trail (stored SEPARATELY).

Every action, decision, and tool call is appended here so we can reconstruct
EXACTLY what touched a target and when. Two properties make it trustworthy:

  * APPEND-ONLY    — we only ever INSERT; there is no update/delete path.
  * TAMPER-EVIDENT — each entry carries an HMAC over (previous HMAC + this
                     entry). Editing, reordering, or deleting any entry breaks
                     the chain from that point on, and because the HMAC is keyed
                     with a secret, an attacker who can write the file still
                     cannot forge a valid chain without the key.

It lives in its OWN SQLite file (default data/audit.db), separate from the
regular datastore and logs, so operational churn can't disturb the record.
Secrets in parameters are redacted before they are written.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    program    TEXT,
    actor      TEXT,
    target     TEXT,
    kind       TEXT,
    params     TEXT,
    decision   TEXT,
    reason     TEXT,
    impact     TEXT,
    prev_hmac  TEXT NOT NULL,
    hmac       TEXT NOT NULL
);
"""


@dataclass
class AuditEntry:
    seq: int
    ts: str
    program: str
    actor: str
    target: str
    kind: str
    decision: str
    reason: str
    impact: str
    hmac: str


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _canonical(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditTrail:
    def __init__(self, key: bytes, db_path: str | Path = "data/audit.db",
                 redactor=None) -> None:
        self._key = key if isinstance(key, bytes) else str(key).encode()
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._redactor = redactor  # optional core.governance.Redactor

    def _last_hmac(self) -> str:
        row = self._conn.execute("SELECT hmac FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hmac"] if row else _GENESIS

    def _compute(self, prev_hmac: str, body: dict) -> str:
        msg = prev_hmac.encode() + _canonical(body)
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def append(self, *, program: str = "", actor: str = "", target: str = "",
               kind: str = "", params: dict | None = None, decision: str = "",
               reason: str = "", impact: str = "") -> int:
        """Append one tamper-evident audit record. Returns its sequence number."""
        params = params or {}
        if self._redactor is not None:
            try:
                params = self._redactor.redact_dict(params)
            except Exception:
                params = {}
        ts = _now()
        body = {"ts": ts, "program": program, "actor": actor, "target": target,
                "kind": kind, "params": params, "decision": decision,
                "reason": reason, "impact": impact}
        with self._lock:
            prev = self._last_hmac()
            h = self._compute(prev, body)
            cur = self._conn.execute(
                "INSERT INTO audit (ts, program, actor, target, kind, params, decision, "
                "reason, impact, prev_hmac, hmac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ts, program, actor, target, kind, json.dumps(params, default=str),
                 decision, reason, impact, prev, h))
            self._conn.commit()
            return int(cur.lastrowid)

    def verify(self) -> tuple[bool, int | None]:
        """
        Recompute the whole chain. Returns (ok, first_bad_seq). ok=True means the
        record is intact; otherwise first_bad_seq is the first tampered entry.
        """
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        prev = _GENESIS
        for r in rows:
            if r["prev_hmac"] != prev:
                return False, int(r["seq"])
            body = {"ts": r["ts"], "program": r["program"], "actor": r["actor"],
                    "target": r["target"], "kind": r["kind"],
                    "params": json.loads(r["params"] or "{}"), "decision": r["decision"],
                    "reason": r["reason"], "impact": r["impact"]}
            if self._compute(prev, body) != r["hmac"]:
                return False, int(r["seq"])
            prev = r["hmac"]
        return True, None

    def recent(self, limit: int = 200, program: str | None = None) -> list[sqlite3.Row]:
        if program:
            return self._conn.execute(
                "SELECT * FROM audit WHERE program=? ORDER BY seq DESC LIMIT ?",
                (program, limit)).fetchall()
        return self._conn.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) c FROM audit").fetchone()["c"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
