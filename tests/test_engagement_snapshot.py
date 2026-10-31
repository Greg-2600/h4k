"""Tests for engagement snapshot export/import and attack-path markdown."""

import pytest
from services.attack_paths import compute_attack_paths, paths_to_markdown
from services.engagement import (
    EngagementStore,
    export_snapshot,
    import_snapshot,
)


@pytest.fixture()
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture()
def eng(store):
    return store.create_engagement("acme", ["10.0.0.0/24"])


def _seed(store, eng_id):
    store.ingest_scan(
        eng_id,
        {
            "hosts": [
                {"address": "10.0.0.5", "services": [{"port": 22, "service": "ssh"}]},
                {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                },
                {
                    "host": "10.0.0.9",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                },
            ],
            "vulns": [
                {
                    "host": "10.0.0.5",
                    "name": "OpenSSH outdated",
                    "severity": "high",
                    "cwe": "CWE-1104",
                },
            ],
        },
    )
    store.add_crown_jewel(eng_id, "10.0.0.9", "DC", 80)


def test_export_snapshot_captures_everything(store, eng):
    _seed(store, eng["id"])
    snap = export_snapshot(store, eng["id"])
    assert snap["format"] == "h4k-engagement"
    assert snap["version"] == 1
    assert len(snap["assets"]) == 2
    assert len(snap["credentials"]) == 1
    assert len(snap["vulns"]) == 1
    assert len(snap["crown_jewels"]) == 1
    assert snap["engagement"]["name"] == "acme"


def test_export_snapshot_of_an_empty_engagement(store, eng):
    snap = export_snapshot(store, eng["id"])
    assert snap["assets"] == []
    assert snap["crown_jewels"] == []


def test_import_snapshot_round_trip(store, eng):
    _seed(store, eng["id"])
    snap = export_snapshot(store, eng["id"])

    other = store.create_engagement("second", ["10.0.0.0/24"])
    result = import_snapshot(store, other["id"], snap)
    assert result["imported"]["assets"] == 2
    assert result["imported"]["services"] == 2
    assert result["imported"]["vulns"] == 1
    assert result["skipped_out_of_scope"] == []
    assert len(store.assets(other["id"])) == 2
    assert len(store.list_crown_jewels(other["id"])) == 1
    creds = store.credentials(other["id"])
    assert creds and creds[0]["user"] == "root"


def test_import_snapshot_skips_out_of_scope_hosts(store, eng):
    _seed(store, eng["id"])
    snap = export_snapshot(store, eng["id"])
    # the importing engagement covers a different range
    narrow = store.create_engagement("narrow", ["192.168.1.0/24"])
    result = import_snapshot(store, narrow["id"], snap)
    assert result["imported"]["assets"] == 0
    assert "10.0.0.5" in result["skipped_out_of_scope"]
    assert store.assets(narrow["id"]) == []


def test_import_snapshot_rejects_garbage(store, eng):
    with pytest.raises(ValueError):
        import_snapshot(store, eng["id"], [])
    with pytest.raises(ValueError):
        import_snapshot(store, eng["id"], {"format": "something-else"})


def test_import_snapshot_tolerates_a_duplicate_crown_jewel(store, eng):
    _seed(store, eng["id"])
    snap = export_snapshot(store, eng["id"])
    import_snapshot(store, eng["id"], snap)  # same engagement -> duplicates
    assert len(store.list_crown_jewels(eng["id"])) == 1


def test_paths_to_markdown_renders_a_writeup(store, eng):
    _seed(store, eng["id"])
    result = compute_attack_paths(store, eng["id"])
    md = paths_to_markdown(result)
    assert "# Attack paths" in md
    assert "10.0.0.5" in md
    assert "10.0.0.9" in md
    assert "T1021" in md


def test_paths_to_markdown_handles_no_paths(store, eng):
    md = paths_to_markdown(compute_attack_paths(store, eng["id"]))
    assert "No evidence-backed path" in md
