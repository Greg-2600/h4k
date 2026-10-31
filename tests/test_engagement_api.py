"""Router-level API tests for the engagement extensions.

These drive the real FastAPI app through TestClient (no live Metasploit, no
network) so the HTTP contract -- status codes, payload shapes, scope
enforcement -- is pinned down, not just the store internals.
"""

from contextlib import asynccontextmanager

import pytest


class FakeMsf:
    @property
    def client(self):
        return self

    @property
    def core(self):
        class _Core:
            @property
            def version(self):
                return {"version": "6.5.0"}

        return _Core()

    def hosts(self, *a, **k):
        return []

    def services(self, *a, **k):
        return []

    def vulns(self, *a, **k):
        return []

    def jobs(self, *a, **k):
        return {}

    def sessions(self, *a, **k):
        return {}

    def current_workspace(self, *a, **k):
        return "default"

    def execute(self, *a, **k):
        return {}


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def _engagement(client, scope="10.0.0.0/24"):
    r = client.post(
        "/api/engagement", json={"name": "lab", "scope": [scope], "notes": ""}
    )
    assert r.status_code == 200, r.text
    return r.json()


def _ingest(client, eng_id):
    report = {
        "hosts": [
            {
                "address": "10.0.0.5",
                "services": [{"port": 22, "service": "ssh"}],
            },
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
                # the same account works on the second host -> lateral pivot
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
            }
        ],
    }
    r = client.post(f"/api/engagement/{eng_id}/ingest", json=report)
    assert r.status_code == 200, r.text
    return r.json()


# ---- crown jewels ---------------------------------------------------------


def test_crown_jewel_crud_over_http(client):
    eng = _engagement(client)
    r = client.post(
        f"/api/engagement/{eng['id']}/crown-jewels",
        json={"host": "10.0.0.9", "label": "DC", "value": 80},
    )
    assert r.status_code == 200, r.text
    cj = r.json()
    assert cj["host"] == "10.0.0.9"

    lst = client.get(f"/api/engagement/{eng['id']}/crown-jewels")
    assert lst.status_code == 200
    assert len(lst.json()["crown_jewels"]) == 1

    d = client.delete(f"/api/engagement/{eng['id']}/crown-jewels/{cj['id']}")
    assert d.status_code == 200
    assert (
        client.get(f"/api/engagement/{eng['id']}/crown-jewels").json()["crown_jewels"]
        == []
    )


def test_crown_jewel_out_of_scope_is_400(client):
    eng = _engagement(client)
    r = client.post(
        f"/api/engagement/{eng['id']}/crown-jewels",
        json={"host": "8.8.8.8", "label": "nope"},
    )
    assert r.status_code == 400
    assert "scope" in r.json()["detail"].lower()


def test_crown_jewel_unknown_engagement_is_404(client):
    r = client.post("/api/engagement/deadbeef/crown-jewels", json={"host": "10.0.0.9"})
    assert r.status_code == 404


def test_crown_jewel_delete_missing_is_404(client):
    eng = _engagement(client)
    r = client.delete(f"/api/engagement/{eng['id']}/crown-jewels/nope")
    assert r.status_code == 404


# ---- attack paths ---------------------------------------------------------


def test_attack_paths_endpoint_returns_a_path(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    client.post(
        f"/api/engagement/{eng['id']}/crown-jewels",
        json={"host": "10.0.0.9", "label": "DC", "value": 80},
    )
    r = client.get(f"/api/engagement/{eng['id']}/attack-paths")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["summary"]["paths"] >= 1
    path = payload["paths"][0]
    assert path["crown_jewel_host"] == "10.0.0.9"
    assert "10.0.0.5" in path["nodes"]
    assert path["score"] > 0


def test_attack_paths_without_crown_jewels_is_empty(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/attack-paths")
    assert r.status_code == 200
    assert r.json()["paths"] == []
    assert r.json()["summary"]["crown_jewels"] == 0


def test_attack_paths_unknown_engagement_is_404(client):
    assert client.get("/api/engagement/deadbeef/attack-paths").status_code == 404


def test_attack_paths_respects_max_depth(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    client.post(f"/api/engagement/{eng['id']}/crown-jewels", json={"host": "10.0.0.9"})
    r = client.get(f"/api/engagement/{eng['id']}/attack-paths?max_depth=1")
    assert r.status_code == 200
    for path in r.json()["paths"]:
        assert path["hops"] <= 1


# ---- ATT&CK ---------------------------------------------------------------


def test_attck_endpoint_maps_findings(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/attck")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["techniques"]
    assert all("detection" in item for item in payload["items"])


def test_attck_unknown_engagement_is_404(client):
    assert client.get("/api/engagement/deadbeef/attck").status_code == 404


def test_attck_catalog_endpoint(client):
    r = client.get("/api/engagement/attck/techniques")
    assert r.status_code == 200
    assert len(r.json()["techniques"]) >= 10


# ---- sandbox seed ---------------------------------------------------------


def test_sandbox_seed_requires_sandbox_mode(client, monkeypatch):
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    r = client.post("/api/engagement/sandbox-seed")
    assert r.status_code == 404


def test_sandbox_seed_creates_a_populated_engagement(client, monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    r = client.post("/api/engagement/sandbox-seed")
    assert r.status_code == 200, r.text
    payload = r.json()
    eng = payload["engagement"]
    assert eng["scope"] == ["10.10.10.0/24"]
    assert payload["summary"]["assets"] == 3
    assert payload["summary"]["verified_credentials"] == 2
    assert (
        len(
            client.get(f"/api/engagement/{eng['id']}/crown-jewels").json()[
                "crown_jewels"
            ]
        )
        == 1
    )


# ---- attack-path export / snapshot / capabilities ---------------------------


def test_attack_paths_markdown_export(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    client.post(
        f"/api/engagement/{eng['id']}/crown-jewels",
        json={"host": "10.0.0.9", "label": "DC", "value": 80},
    )
    r = client.get(f"/api/engagement/{eng['id']}/attack-paths?fmt=md")
    assert r.status_code == 200
    payload = r.json()
    assert payload["fmt"] == "md"
    assert "# Attack paths" in payload["content"]
    assert "10.0.0.9" in payload["content"]


def test_engagement_export_snapshot(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/export")
    assert r.status_code == 200
    snap = r.json()
    assert snap["format"] == "h4k-engagement"
    assert len(snap["assets"]) == 2


def test_engagement_import_snapshot(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    snap = client.get(f"/api/engagement/{eng['id']}/export").json()

    other = _engagement(client, "10.0.0.0/24")
    r = client.post(f"/api/engagement/{other['id']}/import", json=snap)
    assert r.status_code == 200
    assert r.json()["imported"]["assets"] == 2


def test_engagement_import_rejects_a_bad_format(client):
    eng = _engagement(client)
    r = client.post(f"/api/engagement/{eng['id']}/import", json={"format": "nope"})
    assert r.status_code == 400


def test_capabilities_endpoint(client):
    r = client.get("/api/capabilities")
    assert r.status_code == 200
    payload = r.json()
    assert "features" in payload
    assert "tools" in payload
    assert "metasploit" in payload
    assert "storage" in payload
    assert isinstance(payload["warnings"], list)


# ---- flags + next-move -----------------------------------------------------


def test_flags_crud_over_http(client):
    eng = _engagement(client)
    r = client.post(
        f"/api/engagement/{eng['id']}/flags",
        json={"value": "CTF{hello}", "host": "10.0.0.5", "method": "manual"},
    )
    assert r.status_code == 200
    flag_id = r.json()["flag"]["id"]
    assert r.json()["total"] == 1

    r = client.get(f"/api/engagement/{eng['id']}/flags")
    assert r.status_code == 200
    assert r.json()["count"] == 1

    r = client.delete(f"/api/engagement/{eng['id']}/flags/{flag_id}")
    assert r.status_code == 200
    assert r.json()["total"] == 0


def test_flags_detect_endpoint(client):
    eng = _engagement(client)
    r = client.post(
        f"/api/engagement/{eng['id']}/flags/detect",
        json={
            "text": "the flag is CTF{found_it} and hex 0123456789abcdef0123456789abcdef"
        },
    )
    assert r.status_code == 200
    assert r.json()["count"] >= 1
    assert r.json()["total"] >= 1


def test_flags_empty_value_is_400(client):
    eng = _engagement(client)
    r = client.post(f"/api/engagement/{eng['id']}/flags", json={})
    assert r.status_code == 400


def test_next_move_endpoint(client):
    eng = _engagement(client)
    _ingest(client, eng["id"])
    r = client.get(f"/api/engagement/{eng['id']}/next-move")
    assert r.status_code == 200
    payload = r.json()
    assert "moves" in payload
    assert isinstance(payload["moves"], list)


def test_next_move_unknown_engagement_is_404(client):
    assert client.get("/api/engagement/deadbeef/next-move").status_code == 404
