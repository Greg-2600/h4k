# Tests for the offline curated CVE lookup.
from pathlib import Path

import pytest
from schemas import Host, Service, Vuln
from services.cve_lookup import CveDb

CVE_DATA = Path(__file__).resolve().parent.parent / "h4k" / "data" / "cves.json"


@pytest.fixture()
def db():
    assert CVE_DATA.exists(), f"missing CVE dataset at {CVE_DATA}"
    return CveDb(CVE_DATA)


def test_loads_cves(db):
    assert len(db.cves) > 0


def test_match_service_by_product_token(db):
    # OpenSSH banner -> SSH enumeration CVEs (no unrelated sudo/polkit)
    svc = Service(port=22, service="ssh", info="OpenSSH 9.2p1 Debian protocol 2.0")
    ids = [c["id"] for c in db.match_service(svc)]
    assert "CVE-2015-5602" in ids
    assert "CVE-2018-15473" in ids
    # generic sudo/polkit CVEs should not leak in for a bare ssh service
    assert "CVE-2021-4034" not in ids


def test_match_service_postgres(db):
    svc = Service(port=5432, service="postgresql", info="")
    ids = [c["id"] for c in db.match_service(svc)]
    assert "CVE-2021-35942" in ids


def test_no_false_positive_for_cherrypy(db):
    svc = Service(port=8181, service="http", info="CherryPy httpd unknown")
    ids = [c["id"] for c in db.match_service(svc)]
    # curated set has no CherryPy entry; should not pull unrelated http CVEs
    assert "CVE-2021-44228" not in ids


def test_match_refs_by_id(db):
    v = Vuln(name="scan", refs=["CVE-2017-0144"])
    res = db.match_refs(v.refs)
    assert any(c["id"] == "CVE-2017-0144" for c in res)


def test_match_refs_none(db):
    assert db.match_refs([]) == []


def test_enrich_empty_with_no_cves(monkeypatch, db):
    monkeypatch.setattr(db, "cves", [])
    hosts, vulns = [], []
    out = db.enrich(hosts, vulns)
    assert out["services"] == {}
    assert out["vulns"] == {}


def test_enrich_services_map(db):
    host = Host(address="10.0.0.9", services=[Service(port=22, service="ssh")])
    out = db.enrich([host], [])
    assert "10.0.0.9" in out["services"]
    assert any(
        "CVE-2015-5602" in [c["id"] for c in cves]
        for cves in out["services"]["10.0.0.9"].values()
    )


def test_refresh_failed_keeps_db(db, monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **k: (_ for _ in ()).throw(OSError("offline")),
    )
    ok = db.refresh(url="https://invalid.example/x.json", timeout=1)
    assert ok is False
    assert len(db.cves) > 0
