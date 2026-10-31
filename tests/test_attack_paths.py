import pytest
from services.attack_paths import compute_attack_paths
from services.engagement import EngagementStore, ScopeError


@pytest.fixture
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture
def eng(store):
    e = store.create_engagement("acme", ["10.0.0.0/24"])
    report = {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [
                    {"port": 22, "service": "ssh"},
                    {"port": 80, "service": "http"},
                ],
            },
            {"address": "10.0.0.9", "services": [{"port": 22, "service": "ssh"}]},
            {"address": "10.0.0.42", "services": [{"port": 22, "service": "ssh"}]},
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
        ],
        "vulns": [
            {
                "host": "10.0.0.5",
                "name": "OpenSSH outdated",
                "severity": "high",
                "cwe": "CWE-1104",
            },
        ],
    }
    store.ingest_scan(e["id"], report)
    # credential also works on .9 and .42 (lateral movement)
    store.record_credential(
        e["id"],
        "root",
        "toor",
        "ssh",
        origin_host="10.0.0.9",
        origin_port=22,
        verified=True,
    )
    store.record_credential(
        e["id"],
        "root",
        "toor",
        "ssh",
        origin_host="10.0.0.42",
        origin_port=22,
        verified=True,
    )
    return e


def test_crown_jewel_crud(store, eng):
    cj = store.add_crown_jewel(eng["id"], "10.0.0.42", "Domain controller", 90)
    assert cj["host"] == "10.0.0.42"
    assert cj["value"] == 90
    assert len(store.list_crown_jewels(eng["id"])) == 1
    assert store.get_crown_jewel(eng["id"], cj["id"])["label"] == "Domain controller"
    assert store.delete_crown_jewel(eng["id"], cj["id"]) is True
    assert store.list_crown_jewels(eng["id"]) == []


def test_crown_jewel_requires_scope(store, eng):
    with pytest.raises(ScopeError):
        store.add_crown_jewel(eng["id"], "8.8.8.8", "out of scope")


def test_crown_jewel_duplicate_host(store, eng):
    store.add_crown_jewel(eng["id"], "10.0.0.42", "dc")
    with pytest.raises(ValueError):
        store.add_crown_jewel(eng["id"], "10.0.0.42", "dc2")


def test_attack_path_found(store, eng):
    store.add_crown_jewel(eng["id"], "10.0.0.42", "DC", 90)
    result = compute_attack_paths(store, eng["id"])
    assert result["summary"]["paths"] >= 1
    path = result["paths"][0]
    assert path["crown_jewel_host"] == "10.0.0.42"
    assert "10.0.0.5" in path["nodes"]
    assert "10.0.0.42" in path["nodes"]
    assert any(e["type"] == "pivot" for e in path["edges"])
    assert path["score"] > 0


def test_attack_path_no_crown_jewels(store, eng):
    result = compute_attack_paths(store, eng["id"])
    assert result["paths"] == []
    assert result["summary"]["crown_jewels"] == 0


def test_attack_path_single_jewel(store, eng):
    cj = store.add_crown_jewel(eng["id"], "10.0.0.42", "DC", 90)
    result = compute_attack_paths(store, eng["id"], crown_jewel_id=cj["id"])
    assert result["summary"]["crown_jewels"] == 1
    assert all(p["crown_jewel_id"] == cj["id"] for p in result["paths"])


def test_delete_engagement_cascades_crown_jewels(store, eng):
    store.add_crown_jewel(eng["id"], "10.0.0.42", "dc")
    store.delete_engagement(eng["id"])
    assert store.list_crown_jewels(eng["id"]) == []
