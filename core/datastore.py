"""
datastore.py — the single shared SQLite datastore.

Recon writes the inventory here (assets, hosts, urls, parameters); every vuln
module reads that inventory and writes findings here; the dashboard and reporter
read from here. One database, one source of truth.

Design choices made for a beginner's benefit:

  * Plain `sqlite3` (standard library) with a thin hand-written layer — no ORM
    to learn. The SQL is right here in front of you.
  * WAL mode + a write lock so multiple worker threads can use it safely.
  * Findings are DEDUPLICATED: the same bug class on the same URL+parameter is
    one 'finding', but we still record EVERY instance in `finding_instances`.

Status lifecycle of a finding: new -> verified -> reported
(plus 'false_positive' for things verification disproves).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Schema. Kept as one string so it's easy to read top-to-bottom.
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    platform    TEXT,
    handle      TEXT,
    config_path TEXT,
    created_at  TEXT NOT NULL
);

-- Hosts / domains / IPs discovered by recon.
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id  INTEGER NOT NULL REFERENCES programs(id),
    type        TEXT NOT NULL,           -- 'domain' | 'host' | 'ip'
    value       TEXT NOT NULL,
    source      TEXT,                    -- which tool found it
    is_live     INTEGER DEFAULT 0,
    metadata    TEXT,                    -- JSON blob (httpx details etc.)
    created_at  TEXT NOT NULL,
    UNIQUE(program_id, type, value)
);

-- Harvested URLs.
CREATE TABLE IF NOT EXISTS urls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id   INTEGER NOT NULL REFERENCES programs(id),
    url          TEXT NOT NULL,
    host         TEXT,
    status_code  INTEGER,
    content_type TEXT,
    source       TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE(program_id, url)
);

-- Parameters discovered on URLs (query/body/header/path).
CREATE TABLE IF NOT EXISTS parameters (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id    INTEGER NOT NULL REFERENCES programs(id),
    url_id        INTEGER REFERENCES urls(id),
    url           TEXT NOT NULL,
    name          TEXT NOT NULL,
    param_type    TEXT DEFAULT 'query',  -- query | body | header | path | cookie
    example_value TEXT,
    source        TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE(program_id, url, name, param_type)
);

-- The findings table. dedup_key collapses duplicates; instances keep them all.
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id    INTEGER NOT NULL REFERENCES programs(id),
    type          TEXT NOT NULL,          -- e.g. 'xss'
    subtype       TEXT,                   -- 'reflected' | 'stored' | 'dom' | 'blind'
    severity      TEXT,                   -- info|low|medium|high|critical
    status        TEXT NOT NULL DEFAULT 'new',  -- new|verified|reported|false_positive
    url           TEXT,
    parameter     TEXT,
    payload       TEXT,
    context       TEXT,                   -- html_body|attribute|js_string|url|css
    request       TEXT,
    response      TEXT,
    cvss_score    REAL,
    cvss_vector   TEXT,
    title         TEXT,
    description   TEXT,
    evidence      TEXT,                   -- JSON: snippets, csp, dom flow, etc.
    poc_screenshot TEXT,
    poc_video     TEXT,
    dedup_key     TEXT NOT NULL,
    instance_count INTEGER DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(program_id, dedup_key)
);

-- Every individual instance of a finding (even when deduped into one row above).
CREATE TABLE IF NOT EXISTS finding_instances (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    url         TEXT,
    parameter   TEXT,
    payload     TEXT,
    request     TEXT,
    response    TEXT,
    created_at  TEXT NOT NULL
);

-- Blind / out-of-band callback hits (e.g. interactsh), possibly hours later.
CREATE TABLE IF NOT EXISTS callbacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id      INTEGER REFERENCES programs(id),
    finding_id      INTEGER REFERENCES findings(id),
    correlation_id  TEXT,                -- the unique marker we injected
    interaction     TEXT,                -- 'http' | 'dns' | 'smtp'
    source_ip       TEXT,
    origin          TEXT,
    captured_dom    TEXT,
    captured_cookies TEXT,
    raw             TEXT,
    received_at     TEXT NOT NULL
);

-- Runs: lets us resume a long scan and show live progress.
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id  INTEGER NOT NULL REFERENCES programs(id),
    run_uid     TEXT NOT NULL UNIQUE,
    module      TEXT,
    status      TEXT NOT NULL DEFAULT 'running',  -- running|paused|done|failed
    stats       TEXT,                    -- JSON counters
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

-- The resumable work queue. Each candidate is tested independently; a failure
-- or a hit on one NEVER halts the run.
CREATE TABLE IF NOT EXISTS queue_items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES runs(id),
    module        TEXT NOT NULL,
    candidate_key TEXT NOT NULL,         -- stable id so resume skips done work
    candidate     TEXT NOT NULL,         -- JSON describing the candidate
    status        TEXT NOT NULL DEFAULT 'pending', -- pending|in_progress|done|failed
    attempts      INTEGER DEFAULT 0,
    last_error    TEXT,
    updated_at    TEXT NOT NULL,
    UNIQUE(run_id, module, candidate_key)
);

CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_urls_program ON urls(program_id);
CREATE INDEX IF NOT EXISTS idx_params_program ON parameters(program_id);
CREATE INDEX IF NOT EXISTS idx_queue_run_status ON queue_items(run_id, status);

-- ===================================================================
--  Access-control / IDOR module (Prompt 2) shared tables
-- ===================================================================

-- Identity profiles (metadata only — raw secrets live in a gitignored
-- identities file/in memory, never committed). Used by the session manager
-- and shown on the dashboard's identity panel.
CREATE TABLE IF NOT EXISTS identities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id   INTEGER NOT NULL REFERENCES programs(id),
    name         TEXT NOT NULL,           -- e.g. 'userA'
    role         TEXT,                    -- 'high_priv' | 'low_priv' | 'anonymous'
    auth_type    TEXT,                    -- 'bearer' | 'cookie' | 'header' | 'none'
    auth_summary TEXT,                    -- REDACTED summary, e.g. 'bearer eyJ…(82)'
    description  TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE(program_id, name)
);

-- Captured request/response pairs (from mitmproxy or manual import). The raw
-- material the replay+compare engine consumes.
CREATE TABLE IF NOT EXISTS captured_traffic (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id   INTEGER NOT NULL REFERENCES programs(id),
    method       TEXT NOT NULL,
    url          TEXT NOT NULL,
    host         TEXT,
    req_headers  TEXT,                    -- JSON
    req_body     TEXT,
    status_code  INTEGER,
    resp_headers TEXT,                    -- JSON
    resp_body    TEXT,
    captured_as  TEXT,                    -- which identity captured it (if known)
    source       TEXT,                    -- 'mitmproxy' | 'manual' | 'spec'
    created_at   TEXT NOT NULL
);

-- Endpoint catalogue from the three feeds (recon, OpenAPI/Postman, traffic).
CREATE TABLE IF NOT EXISTS endpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id    INTEGER NOT NULL REFERENCES programs(id),
    method        TEXT NOT NULL,
    path_template TEXT NOT NULL,          -- e.g. /api/orders/{id}
    base_url      TEXT,
    params        TEXT,                   -- JSON: [{name,location,example,...}]
    source        TEXT,                   -- 'recon'|'openapi'|'postman'|'traffic'
    meta          TEXT,                   -- JSON: spec metadata, expected responses
    created_at    TEXT NOT NULL,
    UNIQUE(program_id, method, path_template)
);

-- Catalogue of likely object-reference parameters and their enumeration class.
CREATE TABLE IF NOT EXISTS id_params (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id   INTEGER NOT NULL REFERENCES programs(id),
    endpoint     TEXT,                    -- url or path it appears on
    location     TEXT,                    -- path|query|body|header|cookie|hidden
    name         TEXT NOT NULL,
    example_value TEXT,
    id_class     TEXT,                    -- sequential|encoded|uuidv1|uuidv4|unknown
    strategy     TEXT,                    -- how we'd enumerate it (read-only)
    notes        TEXT,
    created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_program ON captured_traffic(program_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_program ON endpoints(program_id);
CREATE INDEX IF NOT EXISTS idx_idparams_program ON id_params(program_id);

-- ===================================================================
--  Validation benchmark (Rung 1)
-- ===================================================================
-- One row per benchmark run -> the regression/trend history.
CREATE TABLE IF NOT EXISTS benchmark_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uid     TEXT NOT NULL UNIQUE,
    profile     TEXT,
    metrics     TEXT,                    -- JSON: per-module/class precision/recall
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

-- Per-item match outcomes for the latest run (TP/FP/FN/needs_review/...).
CREATE TABLE IF NOT EXISTS benchmark_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    benchmark_run INTEGER REFERENCES benchmark_runs(id),
    status        TEXT NOT NULL,         -- tp|fp|fn|needs_review|human_puzzle|no_module
    module        TEXT,
    target        TEXT,
    vuln_class    TEXT,
    location      TEXT,
    manifest_id   TEXT,
    finding_id    INTEGER,
    confidence    REAL,
    note          TEXT,
    created_at    TEXT NOT NULL
);

-- ===================================================================
--  Safety & governance backbone (Phase 1)
-- ===================================================================
-- Cross-process governance flags (kill-switch, dry-run, global halt). The
-- supervisor + dashboard share this; the gateway reads it before every action.
CREATE TABLE IF NOT EXISTS gov_state (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT
);

-- Circuit breakers: per-target anomaly counters that auto-halt when tripped.
CREATE TABLE IF NOT EXISTS circuit_breakers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER,
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,            -- 5xx | error_rate | scope_near_miss | blast_radius
    count      INTEGER DEFAULT 0,
    threshold  INTEGER,
    tripped    INTEGER DEFAULT 0,
    reason     TEXT,
    updated_at TEXT,
    UNIQUE(program_id, target, kind)
);

-- Human-in-the-loop approval queue.
CREATE TABLE IF NOT EXISTS approvals (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER,
    actor      TEXT,
    kind       TEXT,                     -- http | tool | report
    target     TEXT,
    summary    TEXT,
    impact     TEXT,
    params     TEXT,                     -- JSON (redacted)
    status     TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|denied|expired
    created_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT
);

-- Quarantined adversarial content (prompt-injection attempts in target data).
CREATE TABLE IF NOT EXISTS injection_quarantine (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER,
    source     TEXT,                     -- where the content came from (url/header/body)
    severity   TEXT,
    patterns   TEXT,                     -- JSON list of matched patterns
    snippet    TEXT,                     -- redacted excerpt
    created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class Finding:
    """A convenience container used when recording a finding."""

    type: str
    subtype: str = ""
    severity: str = "info"
    url: str = ""
    parameter: str = ""
    payload: str = ""
    context: str = ""
    request: str = ""
    response: str = ""
    title: str = ""
    description: str = ""
    status: str = "new"
    cvss_score: float | None = None
    cvss_vector: str = ""
    evidence: dict[str, Any] | None = None
    poc_screenshot: str = ""
    poc_video: str = ""

    def dedup_key(self) -> str:
        """Same bug class + URL path + parameter -> one finding."""
        from urllib.parse import urlparse

        parsed = urlparse(self.url)
        path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if self.url else ""
        return f"{self.type}|{self.subtype}|{path}|{self.parameter}|{self.context}"


class Datastore:
    """A thin, thread-safe wrapper around one SQLite database file."""

    def __init__(self, db_path: str | Path = "data/findings.db", cipher=None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Optional FieldCipher (Fernet). When set, the high-sensitivity fields —
        # captured request/response headers+bodies, finding request/response
        # blocks (which carry harvested tokens/heapdump secrets), and identity
        # auth material — are encrypted AT REST and transparently decrypted on
        # read. Lower-sensitivity metadata (urls, severities, titles, …) stays in
        # plaintext so the dashboard/reporter can filter and group on it.
        self.cipher = cipher
        # check_same_thread=False + our own lock = safe sharing across workers.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    # -- field-level encryption helpers -----------------------------------
    def _enc(self, value: str | None) -> str:
        """Encrypt a sensitive field for storage (no-op without a cipher)."""
        if not value or self.cipher is None:
            return value or ""
        return self.cipher.encrypt(value)

    def _dec(self, value: str | None) -> str:
        """
        Decrypt a sensitive field on read (no-op without a cipher).

        FieldCipher.decrypt is forgiving: a value that isn't a Fernet token (e.g.
        legacy plaintext written before encryption was enabled) is returned
        unchanged, so reads never crash on a mixed table.
        """
        if value is None or self.cipher is None:
            return value or ""
        return self.cipher.decrypt(value)

    def _decrypt_row(self, row: sqlite3.Row | None, fields: tuple[str, ...]) -> dict | None:
        """Turn a Row into a dict with the named sensitive fields decrypted."""
        if row is None:
            return None
        d = dict(row)
        for f in fields:
            if f in d:
                d[f] = self._dec(d[f])
        return d

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- low-level helpers -------------------------------------------------
    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return cur.fetchall()

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- programs ----------------------------------------------------------
    def upsert_program(self, name: str, platform: str, handle: str, config_path: str) -> int:
        existing = self.query_one("SELECT id FROM programs WHERE name = ?", (name,))
        if existing:
            return int(existing["id"])
        cur = self._execute(
            "INSERT INTO programs (name, platform, handle, config_path, created_at) "
            "VALUES (?,?,?,?,?)",
            (name, platform, handle, config_path, _now()),
        )
        return int(cur.lastrowid)

    # -- inventory: assets / urls / parameters ----------------------------
    def add_asset(
        self,
        program_id: int,
        value: str,
        type_: str = "host",
        source: str = "",
        is_live: bool = False,
        metadata: dict | None = None,
    ) -> None:
        self._execute(
            "INSERT OR IGNORE INTO assets "
            "(program_id, type, value, source, is_live, metadata, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (program_id, type_, value, source, int(is_live),
             json.dumps(metadata or {}), _now()),
        )

    def add_url(
        self,
        program_id: int,
        url: str,
        host: str = "",
        status_code: int | None = None,
        content_type: str = "",
        source: str = "",
    ) -> None:
        self._execute(
            "INSERT OR IGNORE INTO urls "
            "(program_id, url, host, status_code, content_type, source, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (program_id, url, host, status_code, content_type, source, _now()),
        )

    def add_parameter(
        self,
        program_id: int,
        url: str,
        name: str,
        param_type: str = "query",
        example_value: str = "",
        source: str = "",
    ) -> None:
        self._execute(
            "INSERT OR IGNORE INTO parameters "
            "(program_id, url, name, param_type, example_value, source, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (program_id, url, name, param_type, example_value, source, _now()),
        )

    def get_urls(self, program_id: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM urls WHERE program_id = ? ORDER BY id", (program_id,))

    def get_parameters(self, program_id: int) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM parameters WHERE program_id = ? ORDER BY id", (program_id,)
        )

    def get_assets(self, program_id: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM assets WHERE program_id = ? ORDER BY id", (program_id,))

    # -- findings (with dedup) --------------------------------------------
    def record_finding(self, program_id: int, finding: Finding) -> int:
        """
        Insert a finding, deduplicating by (program, dedup_key). Returns the
        finding id. Every call also appends a row to finding_instances so we
        never lose an individual occurrence.
        """
        key = finding.dedup_key()
        evidence_json = json.dumps(finding.evidence or {}, default=str)
        now = _now()
        # The raw request/response can carry harvested secrets (e.g. a heapdump
        # body leaked via SSRF), so they are encrypted at rest.
        enc_request = self._enc(finding.request)
        enc_response = self._enc(finding.response)

        with self._lock:
            existing = self._conn.execute(
                "SELECT id, instance_count FROM findings WHERE program_id = ? AND dedup_key = ?",
                (program_id, key),
            ).fetchone()

            if existing:
                finding_id = int(existing["id"])
                new_count = int(existing["instance_count"]) + 1
                # Keep the highest-signal status/severity; here we just bump count
                # and refresh updated_at. Status changes go through update_status.
                self._conn.execute(
                    "UPDATE findings SET instance_count = ?, updated_at = ? WHERE id = ?",
                    (new_count, now, finding_id),
                )
            else:
                cur = self._conn.execute(
                    "INSERT INTO findings "
                    "(program_id, type, subtype, severity, status, url, parameter, "
                    " payload, context, request, response, cvss_score, cvss_vector, "
                    " title, description, evidence, poc_screenshot, poc_video, "
                    " dedup_key, instance_count, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        program_id, finding.type, finding.subtype, finding.severity,
                        finding.status, finding.url, finding.parameter, finding.payload,
                        finding.context, enc_request, enc_response,
                        finding.cvss_score, finding.cvss_vector, finding.title,
                        finding.description, evidence_json, finding.poc_screenshot,
                        finding.poc_video, key, 1, now, now,
                    ),
                )
                finding_id = int(cur.lastrowid)

            # Always record the individual instance (same encrypted blobs).
            self._conn.execute(
                "INSERT INTO finding_instances "
                "(finding_id, url, parameter, payload, request, response, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (finding_id, finding.url, finding.parameter, finding.payload,
                 enc_request, enc_response, now),
            )
            self._conn.commit()
        return finding_id

    def update_finding_status(self, finding_id: int, status: str) -> None:
        self._execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), finding_id),
        )

    def update_finding_fields(self, finding_id: int, **fields: Any) -> None:
        """Update arbitrary columns on a finding (e.g. poc_screenshot, cvss)."""
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [_now(), finding_id]
        self._execute(f"UPDATE findings SET {cols}, updated_at = ? WHERE id = ?", values)

    def get_findings(self, program_id: int, status: str | None = None) -> list[dict]:
        if status:
            rows = self.query(
                "SELECT * FROM findings WHERE program_id = ? AND status = ? ORDER BY id",
                (program_id, status),
            )
        else:
            rows = self.query(
                "SELECT * FROM findings WHERE program_id = ? ORDER BY id", (program_id,)
            )
        return [self._decrypt_row(r, ("request", "response")) for r in rows]

    def get_finding(self, finding_id: int) -> dict | None:
        row = self.query_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._decrypt_row(row, ("request", "response"))

    # -- blind callbacks ---------------------------------------------------
    def record_callback(
        self,
        program_id: int | None,
        correlation_id: str,
        interaction: str,
        source_ip: str = "",
        origin: str = "",
        captured_dom: str = "",
        captured_cookies: str = "",
        raw: str = "",
        finding_id: int | None = None,
    ) -> int:
        cur = self._execute(
            "INSERT INTO callbacks "
            "(program_id, finding_id, correlation_id, interaction, source_ip, origin, "
            " captured_dom, captured_cookies, raw, received_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (program_id, finding_id, correlation_id, interaction, source_ip, origin,
             captured_dom, captured_cookies, raw, _now()),
        )
        return int(cur.lastrowid)

    def get_callbacks(self, program_id: int | None = None) -> list[sqlite3.Row]:
        if program_id is None:
            return self.query("SELECT * FROM callbacks ORDER BY received_at DESC")
        return self.query(
            "SELECT * FROM callbacks WHERE program_id = ? ORDER BY received_at DESC",
            (program_id,),
        )

    # -- runs & resumable queue -------------------------------------------
    def start_run(self, program_id: int, run_uid: str, module: str = "") -> int:
        cur = self._execute(
            "INSERT INTO runs (program_id, run_uid, module, status, stats, started_at) "
            "VALUES (?,?,?,?,?,?)",
            (program_id, run_uid, module, "running", json.dumps({}), _now()),
        )
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str = "done", stats: dict | None = None) -> None:
        self._execute(
            "UPDATE runs SET status = ?, stats = ?, finished_at = ? WHERE id = ?",
            (status, json.dumps(stats or {}), _now(), run_id),
        )

    def enqueue(self, run_id: int, module: str, candidate_key: str, candidate: dict) -> None:
        self._execute(
            "INSERT OR IGNORE INTO queue_items "
            "(run_id, module, candidate_key, candidate, status, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, module, candidate_key, json.dumps(candidate), "pending", _now()),
        )

    def next_pending(self, run_id: int, module: str) -> sqlite3.Row | None:
        """Atomically claim the next pending candidate (so resume is safe)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM queue_items WHERE run_id = ? AND module = ? AND status = 'pending' "
                "ORDER BY id LIMIT 1",
                (run_id, module),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE queue_items SET status = 'in_progress', attempts = attempts + 1, "
                "updated_at = ? WHERE id = ?",
                (_now(), row["id"]),
            )
            self._conn.commit()
            return row

    def mark_queue_item(self, item_id: int, status: str, error: str = "") -> None:
        self._execute(
            "UPDATE queue_items SET status = ?, last_error = ?, updated_at = ? WHERE id = ?",
            (status, error, _now(), item_id),
        )

    def queue_stats(self, run_id: int) -> dict[str, int]:
        rows = self.query(
            "SELECT status, COUNT(*) AS n FROM queue_items WHERE run_id = ? GROUP BY status",
            (run_id,),
        )
        return {r["status"]: int(r["n"]) for r in rows}

    # -- access-control module: identities --------------------------------
    def upsert_identity(
        self, program_id: int, name: str, role: str = "",
        auth_type: str = "", auth_summary: str = "", description: str = "",
    ) -> int:
        # auth_summary describes the identity's auth material (cookie / bearer /
        # session) — high-sensitivity, so it is encrypted at rest.
        enc_summary = self._enc(auth_summary)
        existing = self.query_one(
            "SELECT id FROM identities WHERE program_id = ? AND name = ?", (program_id, name)
        )
        if existing:
            self._execute(
                "UPDATE identities SET role=?, auth_type=?, auth_summary=?, description=? WHERE id=?",
                (role, auth_type, enc_summary, description, int(existing["id"])),
            )
            return int(existing["id"])
        cur = self._execute(
            "INSERT INTO identities (program_id, name, role, auth_type, auth_summary, description, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (program_id, name, role, auth_type, enc_summary, description, _now()),
        )
        return int(cur.lastrowid)

    def get_identities(self, program_id: int) -> list[dict]:
        rows = self.query("SELECT * FROM identities WHERE program_id = ? ORDER BY id", (program_id,))
        return [self._decrypt_row(r, ("auth_summary",)) for r in rows]

    # -- access-control module: captured traffic --------------------------
    def add_captured(
        self, program_id: int, method: str, url: str, host: str = "",
        req_headers: dict | None = None, req_body: str = "",
        status_code: int | None = None, resp_headers: dict | None = None,
        resp_body: str = "", captured_as: str = "", source: str = "mitmproxy",
    ) -> int:
        # Captured headers carry auth material (Cookie / Authorization) and the
        # bodies carry request/response payloads — all high-sensitivity, so the
        # four fields are encrypted at rest. method/url/host/status stay plaintext
        # so the replay engine can filter on them without decrypting everything.
        cur = self._execute(
            "INSERT INTO captured_traffic "
            "(program_id, method, url, host, req_headers, req_body, status_code, "
            " resp_headers, resp_body, captured_as, source, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (program_id, method, url, host,
             self._enc(json.dumps(req_headers or {})), self._enc(req_body),
             status_code,
             self._enc(json.dumps(resp_headers or {})), self._enc(resp_body),
             captured_as, source, _now()),
        )
        return int(cur.lastrowid)

    def get_captured(self, program_id: int) -> list[dict]:
        rows = self.query(
            "SELECT * FROM captured_traffic WHERE program_id = ? ORDER BY id", (program_id,)
        )
        return [self._decrypt_row(r, ("req_headers", "req_body", "resp_headers", "resp_body"))
                for r in rows]

    # -- access-control module: endpoints + id params --------------------
    def add_endpoint(
        self, program_id: int, method: str, path_template: str, base_url: str = "",
        params: list | None = None, source: str = "recon", meta: dict | None = None,
    ) -> None:
        self._execute(
            "INSERT OR IGNORE INTO endpoints "
            "(program_id, method, path_template, base_url, params, source, meta, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (program_id, method, path_template, base_url, json.dumps(params or []),
             source, json.dumps(meta or {}), _now()),
        )

    def get_endpoints(self, program_id: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM endpoints WHERE program_id = ? ORDER BY id", (program_id,))

    def add_id_param(
        self, program_id: int, name: str, location: str, endpoint: str = "",
        example_value: str = "", id_class: str = "unknown", strategy: str = "", notes: str = "",
    ) -> None:
        self._execute(
            "INSERT INTO id_params "
            "(program_id, endpoint, location, name, example_value, id_class, strategy, notes, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (program_id, endpoint, location, name, example_value, id_class, strategy, notes, _now()),
        )

    def get_id_params(self, program_id: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM id_params WHERE program_id = ? ORDER BY id", (program_id,))

    # -- validation benchmark ---------------------------------------------
    def clear_scan_data(self) -> None:
        """Wipe scan surface + findings (keep programs + benchmark history)."""
        with self._lock:
            for t in ("finding_instances", "findings", "urls", "parameters", "assets",
                      "captured_traffic", "endpoints", "id_params", "callbacks",
                      "queue_items", "runs"):
                self._conn.execute(f"DELETE FROM {t}")
            self._conn.commit()

    def start_benchmark(self, run_uid: str, profile: str) -> int:
        cur = self._execute(
            "INSERT INTO benchmark_runs (run_uid, profile, metrics, started_at) VALUES (?,?,?,?)",
            (run_uid, profile, json.dumps({}), _now()))
        return int(cur.lastrowid)

    def finish_benchmark(self, run_id: int, metrics: dict) -> None:
        self._execute("UPDATE benchmark_runs SET metrics = ?, finished_at = ? WHERE id = ?",
                      (json.dumps(metrics), _now(), run_id))

    def add_benchmark_result(self, benchmark_run: int, status: str, module: str, target: str,
                             vuln_class: str, location: str, manifest_id: str = "",
                             finding_id: int | None = None, confidence: float | None = None,
                             note: str = "") -> None:
        self._execute(
            "INSERT INTO benchmark_results (benchmark_run, status, module, target, vuln_class, "
            "location, manifest_id, finding_id, confidence, note, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (benchmark_run, status, module, target, vuln_class, location, manifest_id,
             finding_id, confidence, note, _now()))

    def clear_benchmark_results(self) -> None:
        self._execute("DELETE FROM benchmark_results", ())

    def get_benchmark_runs(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM benchmark_runs ORDER BY id")

    def get_benchmark_results(self, benchmark_run: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM benchmark_results WHERE benchmark_run = ? ORDER BY id",
                          (benchmark_run,))

    # -- governance backbone ----------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        """Public execute (used by retention/governance helpers)."""
        return self._execute(sql, params)

    def gov_get(self, key: str, default: str = "") -> str:
        row = self.query_one("SELECT value FROM gov_state WHERE key = ?", (key,))
        return row["value"] if row else default

    def gov_set(self, key: str, value: str) -> None:
        self._execute(
            "INSERT INTO gov_state (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, _now()))

    def breaker_bump(self, program_id: int, target: str, kind: str, threshold: int,
                     reason: str = "") -> tuple[int, bool]:
        """Increment a circuit-breaker counter; trip it when it reaches threshold."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, count, tripped FROM circuit_breakers "
                "WHERE program_id=? AND target=? AND kind=?", (program_id, target, kind)).fetchone()
            if row:
                count = int(row["count"]) + 1
                tripped = 1 if count >= threshold else int(row["tripped"])
                self._conn.execute(
                    "UPDATE circuit_breakers SET count=?, tripped=?, threshold=?, reason=?, updated_at=? WHERE id=?",
                    (count, tripped, threshold, reason, _now(), row["id"]))
            else:
                count = 1
                tripped = 1 if count >= threshold else 0
                self._conn.execute(
                    "INSERT INTO circuit_breakers (program_id, target, kind, count, threshold, tripped, reason, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (program_id, target, kind, count, threshold, tripped, reason, _now()))
            self._conn.commit()
            return count, bool(tripped)

    def breaker_tripped(self, program_id: int, target: str) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM circuit_breakers WHERE program_id=? AND target=? AND tripped=1 LIMIT 1",
            (program_id, target))

    def breakers(self, program_id: int) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM circuit_breakers WHERE program_id=? ORDER BY id", (program_id,))

    def reset_breakers(self, program_id: int) -> None:
        self._execute("DELETE FROM circuit_breakers WHERE program_id=?", (program_id,))

    def add_approval(self, program_id: int, actor: str, kind: str, target: str,
                     summary: str, impact: str, params: dict) -> int:
        cur = self._execute(
            "INSERT INTO approvals (program_id, actor, kind, target, summary, impact, params, status, created_at) "
            "VALUES (?,?,?,?,?,?,?, 'pending', ?)",
            (program_id, actor, kind, target, summary, impact, json.dumps(params or {}), _now()))
        return int(cur.lastrowid)

    def get_approval(self, approval_id: int) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM approvals WHERE id=?", (approval_id,))

    def get_approvals(self, program_id: int | None = None, status: str | None = None) -> list[sqlite3.Row]:
        sql, p = "SELECT * FROM approvals WHERE 1=1", []
        if program_id is not None:
            sql += " AND program_id=?"; p.append(program_id)
        if status:
            sql += " AND status=?"; p.append(status)
        return self.query(sql + " ORDER BY id DESC", p)

    def decide_approval(self, approval_id: int, status: str, by: str = "dashboard") -> None:
        self._execute("UPDATE approvals SET status=?, decided_at=?, decided_by=? WHERE id=?",
                      (status, _now(), by, approval_id))

    def quarantine_injection(self, program_id: int, source: str, severity: str,
                             patterns: list, snippet: str) -> int:
        cur = self._execute(
            "INSERT INTO injection_quarantine (program_id, source, severity, patterns, snippet, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (program_id, source, severity, json.dumps(patterns or []), snippet[:500], _now()))
        return int(cur.lastrowid)

    def get_quarantine(self, program_id: int | None = None) -> list[sqlite3.Row]:
        if program_id is None:
            return self.query("SELECT * FROM injection_quarantine ORDER BY id DESC")
        return self.query("SELECT * FROM injection_quarantine WHERE program_id=? ORDER BY id DESC",
                          (program_id,))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
