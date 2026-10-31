# Foothold-to-flag paths: synthetic objectives from captured flags.
from contextlib import asynccontextmanager

import pytest
from services.engagement import EngagementStore
from services.flag_paths import compute_flag_paths, flag_paths_to_markdown
from services.flags import FlagStore


@pytest.fixture()
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


@pytest.fixture()
def flags(tmp_path):
    return FlagStore(tmp_path / "flags.db")


@pytest.fixture()
def eng(store):
    e = store.create_engagement("acme", ["10.0.0.0/24"])
    report = {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [{"port": 22, "service": "ssh"}],
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


def test_paths_reach_flag_hosts(store, eng, flags):
    flags.record(eng["id"], "CTF{db}", host="10.0.0.42", path="/root/flag.txt")
    flags.record(eng["id"], "CTF{web}", host="10.0.0.9")
    out = compute_flag_paths(store, eng["id"], flag_store=flags)
    assert out["summary"]["flags"] == 2
    assert out["flag_hosts"] == ["10.0.0.42", "10.0.0.9"]
    assert out["paths"], "expected foothold->flag chains"
    for path in out["paths"]:
        assert path["flags"], "each path must carry its final-hop flags"
        assert path["techniques"], "ATT&CK chain required"
    assert any(
        f["value"] == "CTF{db}"
        for p in out["paths"]
        if p["crown_jewel_host"] == "10.0.0.42"
        for f in p["flags"]
    )


def test_unplaced_and_isolated_flags_have_no_path(store, eng, flags):
    flags.record(eng["id"], "CTF{nowhere}")  # no host
    flags.record(eng["id"], "CTF{far}", host="10.0.0.99")  # in scope, no edges
    out = compute_flag_paths(store, eng["id"], flag_store=flags)
    assert len(out["unplaced"]) == 1
    assert out["unplaced"][0]["value"] == "CTF{nowhere}"
    assert out["paths"] == []
    assert out["summary"]["best_score"] == 0


def test_no_flags_is_empty(store, eng, flags):
    out = compute_flag_paths(store, eng["id"], flag_store=flags)
    assert out["paths"] == [] and out["summary"]["flags"] == 0


def test_markdown_names_flags_and_chains(store, eng, flags):
    flags.record(eng["id"], "CTF{db}", host="10.0.0.42")
    out = compute_flag_paths(store, eng["id"], flag_store=flags)
    md = flag_paths_to_markdown(out)
    assert "CTF{db}" in md
    assert "10.0.0.42" in md


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    app_state.msf_client = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module._rate_store = None
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def _seed_api_engagement(client):
    r = client.post("/api/engagement", json={"name": "e", "scope": ["10.0.0.0/24"]})
    assert r.status_code == 200, r.text
    eng_id = r.json()["id"]
    client.post(
        f"/api/engagement/{eng_id}/ingest",
        json={
            "hosts": [
                {
                    "address": "10.0.0.5",
                    "services": [{"port": 22, "service": "ssh"}],
                }
            ],
            "credentials": [
                {
                    "host": "10.0.0.5",
                    "port": 22,
                    "service": "ssh",
                    "user": "root",
                    "password": "toor",
                    "verified": True,
                }
            ],
            "vulns": [
                {
                    "host": "10.0.0.5",
                    "name": "OpenSSH outdated",
                    "severity": "high",
                }
            ],
        },
    )
    return eng_id


def test_flag_paths_endpoint_json_and_md(client):
    eng_id = _seed_api_engagement(client)
    r = client.post(
        f"/api/engagement/{eng_id}/flags",
        json={"value": "CTF{x}", "host": "10.0.0.5"},
    )
    assert r.status_code == 200, r.text
    r = client.get(f"/api/engagement/{eng_id}/flag-paths")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["flags"] == 1
    r = client.get(f"/api/engagement/{eng_id}/flag-paths", params={"fmt": "md"})
    assert r.status_code == 200 and "CTF{x}" in r.json()["content"]
    r = client.get("/api/engagement/nope/flag-paths")
    assert r.status_code == 404
