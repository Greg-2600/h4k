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


def test_vsftpd_backdoor_only_matches_the_vulnerable_version(db):
    """Regression: a vsftpd 3.0.3 banner must NOT be flagged as the 2.3.4
    backdoor CVE. The matcher used to match on the service name only, which
    produced a critical false positive on a patched host."""
    patched = Service(port=21, service="ftp", info="vsftpd 3.0.3")
    ids = [
        c["id"] for c in db.match_service(patched, version="3.0.3", product="vsftpd")
    ]
    assert "CVE-2011-2523" not in ids

    vulnerable = Service(port=21, service="ftp", info="vsftpd 2.3.4")
    hits = db.match_service(vulnerable, version="2.3.4", product="vsftpd")
    ids = [c["id"] for c in hits]
    assert "CVE-2011-2523" in ids
    # a version-checked hit says so
    assert hits[0].get("_version_verified") is True


def test_unverified_match_is_marked_not_asserted(db):
    """No version data for the product -> the match stays, but it is not
    presented as confirmed."""
    svc = Service(port=8081, service="http", info="Something 1.2.3")
    hits = db.match_service(svc, version="1.2.3", product="something-unknown")
    for hit in hits:
        assert hit.get("_version_verified") is False


def test_openssh_version_excludes_newer_patched_versions(db):
    svc = Service(port=22, service="ssh", info="OpenSSH 9.6p1")
    ids = [c["id"] for c in db.match_service(svc, version="9.6p1", product="openssh")]
    # CVE-2023-38408 affects up to 9.2
    assert "CVE-2023-38408" not in ids


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


def test_db_covers_modern_lpes(db):
    """The 2025-2026 LPEs must be curated: chwoot (sudo) + Copy Fail (kernel).

    h4k's offline DB previously ended at Baron Samedit/PwnKit-era entries,
    so it would have missed the exact bugs on a vulnerable target."""
    ids = {c["id"] for c in db.cves}
    assert "CVE-2025-32462" in ids
    assert "CVE-2025-32463" in ids
    assert "CVE-2026-31431" in ids
    # and they resolve by ref like every other entry
    assert any(c["id"] == "CVE-2025-32463" for c in db.match_refs(["CVE-2025-32463"]))


def test_db_covers_zoneminder_second_order_sqli(db):
    """CVE-2026-27470 (ZM getNearEvents second-order SQLi), proven live on
    1.36.35 via UNION exfiltration of the Users table."""
    ids = {c["id"] for c in db.cves}
    assert "CVE-2026-27470" in ids
    assert any(c["id"] == "CVE-2026-27470" for c in db.match_refs(["CVE-2026-27470"]))


def test_refresh_url_points_at_real_path():
    """Regression: REFRESH_URL once pointed at /main/data/cves.json (404).

    The dataset lives at h4k/data/cves.json in the repo, so the raw URL
    must contain that path or every refresh silently fails."""
    from services.cve_lookup import REFRESH_URL

    assert REFRESH_URL.endswith("/h4k/data/cves.json"), REFRESH_URL
    assert "/main/h4k/data/cves.json" in REFRESH_URL
