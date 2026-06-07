"""
Tests for the SQLite datastore: dedup behaviour, instances, callbacks, and the
resumable queue.
"""

import pytest

from core.datastore import Datastore, Finding


@pytest.fixture
def store(tmp_path):
    ds = Datastore(db_path=tmp_path / "test.db")
    yield ds
    ds.close()


def test_program_and_inventory_roundtrip(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "config/acme.yml")
    assert pid > 0
    # upsert is idempotent
    assert store.upsert_program("acme", "hackerone", "acme", "config/acme.yml") == pid

    store.add_url(pid, "https://acme.com/search?q=1", host="acme.com", status_code=200)
    store.add_parameter(pid, "https://acme.com/search?q=1", "q", "query", "1")

    assert len(store.get_urls(pid)) == 1
    assert len(store.get_parameters(pid)) == 1


def test_finding_dedup_records_every_instance(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "x")

    f = Finding(
        type="xss",
        subtype="reflected",
        severity="high",
        url="https://acme.com/search?q=1",
        parameter="q",
        payload="<script>alert(1)</script>",
        context="html_body",
    )
    id1 = store.record_finding(pid, f)
    id2 = store.record_finding(pid, f)  # same dedup key

    # Same finding row...
    assert id1 == id2
    findings = store.get_findings(pid)
    assert len(findings) == 1
    assert findings[0]["instance_count"] == 2

    # ...but both instances are preserved.
    instances = store.query(
        "SELECT * FROM finding_instances WHERE finding_id = ?", (id1,)
    )
    assert len(instances) == 2


def test_different_parameter_is_a_separate_finding(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "x")
    store.record_finding(pid, Finding(type="xss", url="https://acme.com/s?q=1", parameter="q"))
    store.record_finding(pid, Finding(type="xss", url="https://acme.com/s?r=1", parameter="r"))
    assert len(store.get_findings(pid)) == 2


def test_status_update_and_filter(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "x")
    fid = store.record_finding(pid, Finding(type="xss", url="https://acme.com/?q=1", parameter="q"))
    store.update_finding_status(fid, "verified")
    assert len(store.get_findings(pid, status="verified")) == 1
    assert len(store.get_findings(pid, status="new")) == 0


def test_callback_recording(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "x")
    store.record_callback(pid, "corr-123", "http", source_ip="203.0.113.9", origin="https://acme.com")
    cbs = store.get_callbacks(pid)
    assert len(cbs) == 1
    assert cbs[0]["correlation_id"] == "corr-123"


def test_resumable_queue(store):
    pid = store.upsert_program("acme", "hackerone", "acme", "x")
    run_id = store.start_run(pid, "run-uid-1", module="xss")

    store.enqueue(run_id, "xss", "cand-1", {"url": "https://acme.com/?q=1", "param": "q"})
    store.enqueue(run_id, "xss", "cand-2", {"url": "https://acme.com/?r=1", "param": "r"})
    # Enqueue duplicate key -> ignored (so resume never double-tests).
    store.enqueue(run_id, "xss", "cand-1", {"url": "https://acme.com/?q=1", "param": "q"})

    stats = store.queue_stats(run_id)
    assert stats.get("pending") == 2

    item = store.next_pending(run_id, "xss")
    assert item is not None
    store.mark_queue_item(item["id"], "done")

    stats = store.queue_stats(run_id)
    assert stats.get("done") == 1
    assert stats.get("pending") == 1
