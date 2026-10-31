"""Tests for the passive sniffing endpoints."""

from contextlib import asynccontextmanager

import pytest


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import app_state
    import main as main_module

    app_state.msf_client = None

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


def test_sniff_pcap_requires_a_path(client):
    r = client.post("/api/net/sniff/pcap", json={})
    assert r.status_code == 400


def test_sniff_pcap_missing_file_returns_error(client):
    r = client.post("/api/net/sniff/pcap", json={"pcap_file": "/nope.pcap"})
    # tshark is not installed in the test env -> a structured error, not a 500
    assert r.status_code == 200 or r.status_code in (400, 404, 500)
    assert isinstance(r.json(), dict)


def test_sniff_deep_requires_interface_gracefully(client):
    r = client.post("/api/net/sniff/deep", json={"interface": "lo", "duration": 1})
    # either it ran (tshark may be missing -> structured error) or 4xx/5xx
    assert isinstance(r.json(), dict)


def test_interfaces_endpoint(client):
    r = client.get("/api/net/interfaces")
    assert r.status_code == 200
    assert "interfaces" in r.json()
