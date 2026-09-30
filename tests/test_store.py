import os
import uuid

import pytest

from cloudsheriff import store as store_module
from cloudsheriff.store import Store


def scan(scan_id, finished):
    return {"scan_id": scan_id, "finished_at": finished}


def update(key="key", label="one"):
    return {
        "key": key, "check_id": "check", "title": "title", "severity": "high",
        "resource_uid": "uid", "resource_name": "name", "region": "region", "account": "account",
        "labels": [label], "compliance": {"CIS-7.0": ["5.3"]}, "last_status": "PASS",
        "evidence": None, "evidence_hash": None, "first_seen": "a", "last_evaluated": "b", "gone": False,
    }


def test_store_round_trip_has_no_id():
    with Store("mem://") as store:
        store.save_scan(scan("s1", "2026-01-01T00:00:00Z"), [], {"key": update()}, [])
        state = store.load_state()
        assert state["key"]["key"] == "key" and "id" not in state["key"]


def test_store_labels_and_compliance_round_trip():
    with Store("mem://") as store:
        store.save_scan(scan("s1", "2026-01-01T00:00:00Z"), [], {"key": update(label="raw")}, [])
        record = store.load_state()["key"]
        assert record["labels"] == ["raw"] and record["compliance"] == {"CIS-7.0": ["5.3"]}


def test_store_last_scan_returns_most_recent():
    with Store("mem://") as store:
        store.save_scan(scan("s1", "2026-01-01T00:00:00Z"), [], {}, [])
        store.save_scan(scan("s2", "2026-01-02T00:00:00Z"), [], {}, [])
        assert store.last_scan()["scan_id"] == "s2"


def test_store_upsert_replaces_record_fully():
    with Store("mem://") as store:
        store.save_scan(scan("s1", "2026-01-01T00:00:00Z"), [], {"key": {**update(), "obsolete": True}}, [])
        store.save_scan(scan("s2", "2026-01-02T00:00:00Z"), [], {"key": update(label="two")}, [])
        record = store.load_state()["key"]
        assert record["labels"] == ["two"] and "obsolete" not in record


@pytest.mark.skipif(not os.environ.get("SURREAL_TEST_URL"), reason="needs a SurrealDB server; embedded mem:// returns [] for missing tables")
def test_fresh_server_database_reads_empty(monkeypatch):
    # SurrealDB 3.x servers raise NotFoundError when selecting a table that does not exist yet.
    monkeypatch.setattr(store_module, "DB", f"test_{uuid.uuid4().hex[:8]}")
    with Store(os.environ["SURREAL_TEST_URL"], "root", "root") as store:
        assert store.load_state() == {}
        assert store.last_scan() is None


def test_store_duplicate_scan_is_atomic():
    with Store("mem://") as store:
        store.save_scan(scan("s1", "2026-01-01T00:00:00Z"), [], {"key": update(label="before")}, [])
        with pytest.raises(Exception):
            store.save_scan(scan("s1", "2026-01-02T00:00:00Z"), [], {"key": update(label="after")}, [])
        assert store.load_state()["key"]["labels"] == ["before"]
