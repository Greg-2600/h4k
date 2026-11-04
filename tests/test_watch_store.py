"""Lab Watch store: snapshots, diffs, pruning, scope enforcement (offline)."""

import pytest
from services.engagement import EngagementStore


@pytest.fixture
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture
def eng(store):
    return store.create_engagement("watch lab", ["10.0.0.0/24"])


def _report(extra_host=True):
    hosts = [
        {
            "address": "10.0.0.5",
            "services": [
                {"port": 22, "proto": "tcp", "service": "ssh", "version": "9.2p1"}
            ],
        }
    ]
    if extra_host:
        hosts.append(
            {"address": "192.168.99.9", "services": [{"port": 80, "service": "http"}]}
        )
    return {
        "hosts": hosts,
        "vulns": [
            {"host": "10.0.0.5", "name": "CVE-2021-1", "port": 22, "severity": "high"}
        ],
    }


def test_first_snapshot_is_baseline(store, eng):
    res = store.record_watch_snapshot(eng["id"], _report())
    assert res["diff"]["first_baseline"] is True
    assert res["diff"]["change_count"] == 0
    assert res["notable"] is False


def test_out_of_scope_hosts_never_enter_history(store, eng):
    store.record_watch_snapshot(eng["id"], _report())
    snaps = store._query(
        "SELECT snapshot_json FROM watch_snapshots WHERE engagement_id=?", (eng["id"],)
    )
    import json

    hosts = json.loads(snaps[0]["snapshot_json"])["hosts"]
    assert "10.0.0.5" in hosts
    assert "192.168.99.9" not in hosts


def test_identical_rescan_is_quiet(store, eng):
    store.record_watch_snapshot(eng["id"], _report())
    res = store.record_watch_snapshot(eng["id"], _report())
    assert res["diff"]["change_count"] == 0
    assert res["notable"] is False


def test_new_service_is_a_notable_change(store, eng):
    store.record_watch_snapshot(eng["id"], _report())
    report = _report()
    report["hosts"][0]["services"].append(
        {"port": 443, "proto": "tcp", "service": "https"}
    )
    res = store.record_watch_snapshot(eng["id"], report, source="manual")
    assert res["notable"] is True
    assert {(s["host"], s["port"]) for s in res["diff"]["new_services"]} == {
        ("10.0.0.5", 443)
    }
    assert "new service(s)" in res["summary"]


def test_changes_lists_events_newest_first(store, eng):
    store.record_watch_snapshot(eng["id"], _report())
    report = _report()
    report["hosts"][0]["services"].append({"port": 443, "service": "https"})
    store.record_watch_snapshot(eng["id"], report)
    changes = store.watch_changes(eng["id"])
    assert len(changes) == 2
    assert changes[0]["diff"]["change_count"] > 0
    st = store.watch_status(eng["id"])
    assert st["snapshots"] == 2
    assert st["last_change"] is not None


def test_retention_prunes_old_snapshots(store, eng):
    for _ in range(35):
        store.record_watch_snapshot(eng["id"], _report())
    assert store.watch_status(eng["id"])["snapshots"] <= 30


def test_unknown_engagement_raises(store):
    with pytest.raises(ValueError, match="unknown engagement"):
        store.record_watch_snapshot("nope", {"hosts": []})
