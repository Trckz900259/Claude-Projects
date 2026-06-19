"""
app.py — the Streamlit dashboard.

Read-only view over the shared datastore (data/findings.db). Launch it with:

    bbp dashboard               # convenience wrapper
    # or directly:
    BBP_DB_PATH=data/findings.db streamlit run dashboard/app.py

Sections:
  * Overview          — programs, live run progress, headline counts.
  * Findings          — filter by severity/type/status; click in for full detail.
  * Recon & coverage  — discovered surface, tested vs untested.
  * Blind callbacks   — out-of-band hits, auto-refreshing.
  * Charts            — severity distribution + findings timeline.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

DB_PATH = os.environ.get("BBP_DB_PATH", "data/findings.db")

SEV_ORDER = ["critical", "high", "medium", "low", "informational", "info"]
SEV_COLORS = {
    "critical": "#c0392b", "high": "#e74c3c", "medium": "#e67e22",
    "low": "#f1c40f", "informational": "#95a5a6", "info": "#95a5a6",
}

st.set_page_config(page_title="Bug Bounty Platform", page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------------------
# Data access (fresh connection each run so we always see the latest)
# ---------------------------------------------------------------------------
def connect() -> sqlite3.Connection | None:
    if not Path(DB_PATH).exists():
        return None
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def df(conn, sql, params=()) -> pd.DataFrame:
    try:
        return pd.read_sql_query(sql, conn, params=params)
    except Exception:
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# Header / program selection
# ---------------------------------------------------------------------------
st.title("🛡️ Bug Bounty Platform — Dashboard")
st.caption(f"Datastore: `{DB_PATH}` · authorized testing only")

conn = connect()
if conn is None:
    st.warning(f"No datastore found at `{DB_PATH}`. Run `bbp recon` / `bbp scan` first.")
    st.stop()

programs = df(conn, "SELECT * FROM programs ORDER BY name")
if programs.empty:
    st.info("The datastore exists but has no programs yet. Run `bbp recon <config>`.")
    st.stop()

with st.sidebar:
    st.header("Program")
    name = st.selectbox("Select program", programs["name"].tolist())
    program = programs[programs["name"] == name].iloc[0]
    pid = int(program["id"])
    st.write(f"**Platform:** {program['platform']}")
    st.write(f"**Handle:** {program['handle']}")
    if st.button("🔄 Refresh now"):
        st.rerun()


# ---------------------------------------------------------------------------
# Load this program's data
# ---------------------------------------------------------------------------
findings = df(conn, "SELECT * FROM findings WHERE program_id = ? ORDER BY id", (pid,))
urls = df(conn, "SELECT * FROM urls WHERE program_id = ?", (pid,))
params = df(conn, "SELECT * FROM parameters WHERE program_id = ?", (pid,))
assets = df(conn, "SELECT * FROM assets WHERE program_id = ?", (pid,))
callbacks = df(conn, "SELECT * FROM callbacks WHERE program_id = ? ORDER BY received_at DESC", (pid,))
runs = df(conn, "SELECT * FROM runs WHERE program_id = ? ORDER BY id DESC", (pid,))
identities = df(conn, "SELECT * FROM identities WHERE program_id = ? ORDER BY id", (pid,))

tab_over, tab_find, tab_recon, tab_ident, tab_cb, tab_charts, tab_valid, tab_safety = st.tabs(
    ["Overview", "Findings", "Recon & coverage", "Identities", "Blind callbacks",
     "Charts", "Validation", "Safety & Governance"]
)

# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
with tab_over:
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Findings", len(findings))
    c2.metric("Verified", int((findings["status"] == "verified").sum()) if not findings.empty else 0)
    c3.metric("URLs", len(urls))
    c4.metric("Parameters", len(params))
    c5.metric("Blind callbacks", len(callbacks))

    st.subheader("Live run progress")
    if runs.empty:
        st.info("No runs yet.")
    else:
        latest = runs.iloc[0]
        q = df(conn,
               "SELECT status, COUNT(*) n FROM queue_items WHERE run_id = ? GROUP BY status",
               (int(latest["id"]),))
        counts = {r["status"]: int(r["n"]) for _, r in q.iterrows()} if not q.empty else {}
        total = sum(counts.values()) or 1
        done = counts.get("done", 0) + counts.get("failed", 0)
        st.write(f"Latest run **{latest['run_uid']}** ({latest['module']}) — status: **{latest['status']}**")
        st.progress(done / total, text=f"{done}/{total} candidates processed")
        cc1, cc2, cc3 = st.columns(3)
        cc1.metric("Pending", counts.get("pending", 0))
        cc2.metric("Done", counts.get("done", 0))
        cc3.metric("Failed", counts.get("failed", 0))

# ---------------------------------------------------------------------------
# Findings (filterable + drill-in)
# ---------------------------------------------------------------------------
with tab_find:
    if findings.empty:
        st.info("No findings yet. Run `bbp scan <config> --module xss`.")
    else:
        f1, f2, f3 = st.columns(3)
        sev_opts = sorted(findings["severity"].dropna().unique(),
                          key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 99)
        sev_sel = f1.multiselect("Severity", sev_opts, default=sev_opts)
        type_opts = sorted(findings["subtype"].dropna().unique())
        type_sel = f2.multiselect("Type", type_opts, default=type_opts)
        status_opts = sorted(findings["status"].dropna().unique())
        status_sel = f3.multiselect("Status", status_opts, default=status_opts)

        view = findings[
            findings["severity"].isin(sev_sel)
            & findings["subtype"].isin(type_sel)
            & findings["status"].isin(status_sel)
        ]
        st.write(f"**{len(view)}** finding(s) match.")
        st.dataframe(
            view[["id", "subtype", "severity", "status", "url", "parameter", "context", "title"]],
            use_container_width=True, hide_index=True,
        )

        st.subheader("Finding detail")
        if not view.empty:
            fid = st.selectbox("Open finding #", view["id"].tolist())
            row = findings[findings["id"] == fid].iloc[0]
            d1, d2 = st.columns(2)
            with d1:
                st.markdown(f"### {row['title']}")
                st.write(f"**Type:** {row['subtype']}  |  **Severity:** {row['severity']}  |  **Status:** {row['status']}")
                if pd.notna(row["cvss_score"]) and row["cvss_score"]:
                    st.write(f"**CVSS:** {row['cvss_score']} — `{row['cvss_vector']}`")
                st.write(f"**URL:** `{row['url']}`")
                if row["parameter"]:
                    st.write(f"**Parameter:** `{row['parameter']}`  |  **Context:** {row['context']}")
                if row["payload"]:
                    st.write("**Payload:**")
                    st.code(row["payload"])
                st.write(row["description"])
            with d2:
                shot = row["poc_screenshot"]
                if shot and Path(shot).exists():
                    st.image(shot, caption="Proof-of-concept screenshot", use_container_width=True)
                else:
                    st.info("No screenshot (unverified or PoC not captured).")

            if row["request"]:
                with st.expander("HTTP request"):
                    st.code(row["request"], language="http")
            if row["response"]:
                with st.expander("HTTP response"):
                    st.code(str(row["response"])[:8000], language="http")

            # Side-by-side proof for access-control (IDOR/BOLA) findings.
            try:
                ev = json.loads(row["evidence"] or "{}")
            except Exception:
                ev = {}
            if ev.get("owner_response") and ev.get("attacker_response"):
                st.markdown("**Side-by-side proof** (same object, two of my own identities)")
                sb1, sb2 = st.columns(2)
                with sb1:
                    st.caption("① Legitimate owner")
                    st.code(str(ev.get("owner_response"))[:4000], language="http")
                with sb2:
                    st.caption("② Attacker identity — same object")
                    st.code(str(ev.get("attacker_response"))[:4000], language="http")

# ---------------------------------------------------------------------------
# Identities (access-control)
# ---------------------------------------------------------------------------
with tab_ident:
    st.subheader("Configured identity profiles")
    st.caption("Access-control testing uses two or more accounts YOU control "
               "(own-accounts-only). The 'victim' is always one of your own accounts.")
    if identities.empty:
        st.info("No identities configured. Add them to your gitignored identities file "
                "and run `bbp identities <config>`.")
    else:
        st.dataframe(
            identities[["name", "role", "auth_type", "auth_summary", "description"]],
            use_container_width=True, hide_index=True,
        )
        n_auth = int((identities["role"] != "anonymous").sum())
        if n_auth >= 2:
            st.success(f"✓ {n_auth} authenticated identities — ready for access-control testing.")
        else:
            st.warning(f"⚠ Only {n_auth} authenticated identity(ies); need ≥ 2.")


# ---------------------------------------------------------------------------
# Recon & coverage
# ---------------------------------------------------------------------------
with tab_recon:
    r1, r2, r3 = st.columns(3)
    r1.metric("Hosts / assets", len(assets))
    r2.metric("URLs discovered", len(urls))
    r3.metric("Parameters discovered", len(params))

    st.subheader("Coverage (tested vs untested)")
    tested_params = set()
    if not findings.empty:
        tested_params = set(zip(findings["url"].fillna(""), findings["parameter"].fillna("")))
    total_params = len(params)
    tested = 0
    if not params.empty:
        param_pairs = set(zip(params["url"], params["name"]))
        # a param counts as 'tested' if it appears on any finding (any status)
        tested = len({p for p in param_pairs if p in tested_params})
    untested = max(0, total_params - tested)
    cov = px.pie(
        names=["tested", "untested"], values=[tested, untested],
        color=["tested", "untested"],
        color_discrete_map={"tested": "#27ae60", "untested": "#bdc3c7"},
        title="Parameter coverage",
    )
    st.plotly_chart(cov, use_container_width=True)

    if not assets.empty:
        st.subheader("Assets")
        st.dataframe(assets[["type", "value", "source", "is_live"]],
                     use_container_width=True, hide_index=True)

# ---------------------------------------------------------------------------
# Blind callbacks (auto-refreshing)
# ---------------------------------------------------------------------------
with tab_cb:
    st.subheader("Out-of-band / blind-XSS callbacks")
    st.caption("These can arrive hours after a scan. Keep `bbp callbacks` running.")

    def _render_callbacks():
        cb = df(connect(),
                "SELECT * FROM callbacks WHERE program_id = ? ORDER BY received_at DESC",
                (pid,))
        if cb.empty:
            st.info("No callbacks recorded yet.")
        else:
            st.success(f"{len(cb)} callback(s) recorded.")
            st.dataframe(
                cb[["received_at", "correlation_id", "interaction", "source_ip", "origin"]],
                use_container_width=True, hide_index=True,
            )

    # Auto-refresh this panel every 5s if the Streamlit version supports fragments.
    if hasattr(st, "fragment"):
        st.fragment(run_every="5s")(_render_callbacks)()
    else:
        _render_callbacks()

# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
with tab_charts:
    if findings.empty:
        st.info("No findings to chart yet.")
    else:
        ch1, ch2 = st.columns(2)
        with ch1:
            sev_counts = findings["severity"].value_counts().reset_index()
            sev_counts.columns = ["severity", "count"]
            fig = px.bar(
                sev_counts, x="severity", y="count", color="severity",
                color_discrete_map=SEV_COLORS, title="Severity distribution",
            )
            st.plotly_chart(fig, use_container_width=True)
        with ch2:
            ts = findings.copy()
            ts["created_at"] = pd.to_datetime(ts["created_at"], errors="coerce")
            ts = ts.dropna(subset=["created_at"]).sort_values("created_at")
            if not ts.empty:
                ts["cumulative"] = range(1, len(ts) + 1)
                fig2 = px.line(ts, x="created_at", y="cumulative",
                               title="Findings over time (cumulative)", markers=True)
                st.plotly_chart(fig2, use_container_width=True)


# ---------------------------------------------------------------------------
# Validation (benchmark precision/recall, regression trend, gap log)
# ---------------------------------------------------------------------------
with tab_valid:
    st.subheader("Module validation (benchmark vs. ground truth)")
    st.caption("Point the dashboard at the benchmark DB to see this: "
               "`bbp dashboard --db data/benchmark.db`. Runs: `bbp benchmark`.")
    bruns = df(conn, "SELECT * FROM benchmark_runs ORDER BY id")
    if bruns.empty:
        st.info("No benchmark runs yet. Run `bbp benchmark validation/lab_profile.local.yml`.")
    else:
        latest = bruns.iloc[-1]
        try:
            metrics = json.loads(latest["metrics"] or "{}")
        except Exception:
            metrics = {}
        by_module = metrics.get("by_module", {})

        st.markdown(f"**Latest run** `{latest['run_uid']}` · {len(bruns)} run(s) in history")
        rows = []
        recs = {r["module"]: r for r in metrics.get("threshold_recs", [])}
        for mod, m in sorted(by_module.items()):
            if mod in ("?", "", "sqli"):
                continue
            rec = recs.get(mod, {})
            rows.append({"module": mod, "TP": m.get("tp"), "FP": m.get("fp"),
                         "FN": m.get("fn", 0) + m.get("surfaced_low", 0),
                         "precision": m.get("precision"), "recall": m.get("recall"),
                         "rec. threshold": rec.get("recommended")})
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # Regression trend across runs (precision & recall per module).
        st.subheader("Regression trend")
        trend = []
        for _, r in bruns.iterrows():
            try:
                mm = json.loads(r["metrics"] or "{}").get("by_module", {})
            except Exception:
                mm = {}
            for mod, m in mm.items():
                if mod in ("?", "", "sqli"):
                    continue
                if m.get("precision") is not None:
                    trend.append({"run": int(r["id"]), "module": mod,
                                  "precision": m.get("precision"), "recall": m.get("recall")})
        if trend:
            tdf = pd.DataFrame(trend)
            c1, c2 = st.columns(2)
            with c1:
                st.plotly_chart(px.line(tdf, x="run", y="precision", color="module",
                                        markers=True, title="Precision over runs", range_y=[0, 1.05]),
                                use_container_width=True)
            with c2:
                st.plotly_chart(px.line(tdf, x="run", y="recall", color="module",
                                        markers=True, title="Recall over runs", range_y=[0, 1.05]),
                                use_container_width=True)

        # Gap log (latest run).
        st.subheader("Gap log (module-improvement backlog)")
        gl = df(conn,
                "SELECT status, module, target, vuln_class, location, note FROM benchmark_results "
                "WHERE benchmark_run = ? AND status IN "
                "('fn','surfaced_low','no_module','human_puzzle') ORDER BY status",
                (int(latest["id"]),))
        if gl.empty:
            st.success("No gaps in the latest run.")
        else:
            st.dataframe(gl, use_container_width=True, hide_index=True)


# ---------------------------------------------------------------------------
# Safety & Governance (supervisor flags, breakers, approvals, audit, usage)
# ---------------------------------------------------------------------------
with tab_safety:
    st.subheader("Safety & governance state")
    st.caption("Live supervisor controls and the tamper-evident record. "
               "Actions here write back to the datastore.")

    def _gov_get(key, default=None):
        """Fetch a single gov_state value (None/default if absent)."""
        g = df(conn, "SELECT value FROM gov_state WHERE key = ?", (key,))
        return g.iloc[0]["value"] if not g.empty else default

    def _gov_set(key, value):
        """Upsert a gov_state flag with the current UTC timestamp."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO gov_state(key, value, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at",
            (key, value, now),
        )
        conn.commit()

    kill = _gov_get("kill_switch", "0")
    dry = _gov_get("dry_run", "0")
    halted = _gov_get("halted", "0")
    halted_reason = _gov_get("halted_reason")

    # ----- prominent status banner -----
    if kill == "1" or halted == "1":
        bits = []
        if kill == "1":
            bits.append("KILL-SWITCH ENGAGED")
        if halted == "1":
            bits.append("HALTED" + (f" — {halted_reason}" if halted_reason else ""))
        st.error("🔴 " + "  ·  ".join(bits) + " — automated actions are blocked.")
    else:
        st.success("🟢 Operational — no kill-switch, not halted.")

    s1, s2, s3 = st.columns(3)
    s1.metric("Kill-switch", "ON" if kill == "1" else "off")
    s2.metric("Halted", "YES" if halted == "1" else "no")
    s3.metric("Dry-run", "ON" if dry == "1" else "off")

    # ----- supervisor controls -----
    st.markdown("**Supervisor controls**")
    cc1, cc2, cc3 = st.columns([1, 1, 2])
    with cc1:
        if st.button("🔴 Engage kill-switch", key="gov_kill_engage"):
            _gov_set("kill_switch", "1")
            _gov_set("halted", "1")
            _gov_set("halted_reason", "kill-switch engaged from dashboard")
            st.rerun()
    with cc2:
        if st.button("✅ Clear kill-switch / halt", key="gov_kill_clear"):
            _gov_set("kill_switch", "0")
            _gov_set("halted", "0")
            _gov_set("halted_reason", "")
            st.rerun()
    with cc3:
        new_dry = st.checkbox("Dry-run mode (simulate, don't act)",
                              value=(dry == "1"), key="gov_dry_run")
        if new_dry != (dry == "1"):
            _gov_set("dry_run", "1" if new_dry else "0")
            st.rerun()

    # ----- usage governor meter -----
    st.markdown("**Usage governor (budget headroom)**")
    try:
        from core.usage import UsageGovernor
        snap = UsageGovernor(
            daily_budget=0, rolling_budget=0,
            state_path=str(Path(DB_PATH).parent / "usage.json"),
        ).snapshot()
        u1, u2 = st.columns(2)
        with u1:
            st.progress(min(1.0, max(0.0, float(snap["daily_pct"]))),
                        text=f"Daily {snap['daily_pct'] * 100:.0f}%")
        with u2:
            st.progress(min(1.0, max(0.0, float(snap["rolling_pct"]))),
                        text=f"Rolling {snap['rolling_pct'] * 100:.0f}%")
        st.caption("Automated spend halts at 0.85 (85%) of either budget; "
                   "the remaining 15% is reserved for interactive use. "
                   "A budget of 0 means unlimited (shown as 0%).")
    except Exception as exc:
        st.info(f"Usage governor snapshot unavailable: {exc}")

    # ----- circuit breakers -----
    st.markdown("**Circuit breakers**")
    breakers = df(conn,
                  "SELECT target, kind, count, threshold, tripped, reason, updated_at "
                  "FROM circuit_breakers ORDER BY tripped DESC, updated_at DESC")
    if breakers.empty:
        st.info("No circuit breakers recorded.")
    else:
        n_tripped = int((breakers["tripped"] == 1).sum())
        if n_tripped:
            st.error(f"🔴 {n_tripped} breaker(s) tripped.")
        styled = breakers.style.apply(
            lambda row: ["background-color: #c0392b; color: white"
                         if row["tripped"] == 1 else "" for _ in row],
            axis=1,
        )
        st.dataframe(styled, use_container_width=True, hide_index=True)

    # ----- human-in-the-loop approvals -----
    st.markdown("**Pending approvals (human-in-the-loop)**")
    pending = df(conn,
                 "SELECT id, program_id, actor, kind, target, summary, impact, created_at "
                 "FROM approvals WHERE status = 'pending' ORDER BY created_at",
                 ())
    if pending.empty:
        st.success("No pending approvals.")
    else:
        st.caption(f"{len(pending)} request(s) awaiting a decision.")
        for _, ap in pending.iterrows():
            aid = int(ap["id"])
            with st.container():
                st.markdown(
                    f"**#{aid}** · `{ap['kind']}` · target `{ap['target']}` "
                    f"· actor `{ap['actor']}`"
                )
                if ap["summary"]:
                    st.write(ap["summary"])
                if ap["impact"]:
                    st.caption(f"Impact: {ap['impact']}")
                a1, a2, _ = st.columns([1, 1, 4])
                if a1.button("✅ Approve", key=f"approve_{aid}"):
                    conn.execute(
                        "UPDATE approvals SET status = ?, decided_at = ?, "
                        "decided_by = 'dashboard' WHERE id = ?",
                        ("approved", datetime.now(timezone.utc).isoformat(), aid),
                    )
                    conn.commit()
                    st.rerun()
                if a2.button("⛔ Deny", key=f"deny_{aid}"):
                    conn.execute(
                        "UPDATE approvals SET status = ?, decided_at = ?, "
                        "decided_by = 'dashboard' WHERE id = ?",
                        ("denied", datetime.now(timezone.utc).isoformat(), aid),
                    )
                    conn.commit()
                    st.rerun()
                st.divider()

    # ----- injection quarantine -----
    st.markdown("**Injection quarantine (flagged adversarial content)**")
    quar = df(conn,
              "SELECT created_at, source, severity, patterns, snippet "
              "FROM injection_quarantine ORDER BY id DESC LIMIT 100")
    if quar.empty:
        st.success("Nothing quarantined.")
    else:
        st.caption(f"{len(quar)} quarantined item(s) (most recent first).")
        st.dataframe(quar, use_container_width=True, hide_index=True)

    # ----- tamper-evident audit trail (separate DB) -----
    st.markdown("**Audit trail (tamper-evident, separate store)**")
    audit_path = Path(DB_PATH).parent / "audit.db"
    if not audit_path.exists():
        st.info(f"No audit store at `{audit_path}` yet.")
    else:
        try:
            aconn = sqlite3.connect(str(audit_path))
            aconn.row_factory = sqlite3.Row
            total = df(aconn, "SELECT COUNT(*) AS c FROM audit")
            n_total = int(total.iloc[0]["c"]) if not total.empty else 0
            recent = df(aconn,
                        "SELECT seq, ts, actor, target, kind, decision, reason, impact "
                        "FROM audit ORDER BY seq DESC LIMIT 50")
            aconn.close()
            st.caption(f"{n_total} total entries · showing the most recent "
                       f"{len(recent)}. Verify the HMAC chain with "
                       "`bbp audit-verify`.")
            if recent.empty:
                st.info("Audit store exists but has no entries yet.")
            else:
                st.dataframe(recent, use_container_width=True, hide_index=True)
        except Exception as exc:
            st.info(f"Could not read audit store: {exc}")
