# Tests for the default-credential archive and service matching.
from pathlib import Path

import pytest
from schemas import Service
from services.creds import CredArchive

CREDS_DATA = Path(__file__).resolve().parent.parent / "h4k" / "data" / "creds.json"


@pytest.fixture()
def archive():
    assert CREDS_DATA.exists(), f"missing creds dataset at {CREDS_DATA}"
    return CredArchive(CREDS_DATA)


def test_loads_archive(archive):
    assert len(archive.universal) > 0
    assert len(archive.vendors) > 0


def test_universal_has_admin_admin(archive):
    users = {c["user"] for c in archive.universal}
    assert "admin" in users
    assert any(c["pass"] == "admin" for c in archive.universal)
    assert any(
        c["user"] == "pi" and c["pass"] == "raspberry" for c in archive.universal
    )


def test_match_fingerprint_by_vendor(archive):
    creds = archive.match_fingerprints(["linksys wrt54g", "http server"])
    # should pull linksys creds
    assert any("linksys" in str(c.get("desc", "")).lower() for c in creds)


def test_match_fingerprint_no_hits(archive):
    assert archive.match_fingerprints([]) == []
    assert archive.match_fingerprints(["totally-unknown-vendor"]) == []


def test_universal_for_service(archive):
    svc = Service(port=22, service="ssh")
    cs = archive.universal_for_service(svc)
    assert any(c["user"] == "pi" for c in cs)  # raspberry pi ssh cred
    assert any(c["user"] == "root" for c in cs)


def test_vendor_for_service_filters(archive):
    creds = archive.match_fingerprints(["raspberry pi"])
    svc = Service(port=22, service="ssh")
    cs = archive.vendor_for_service(creds, svc)
    assert any(c["user"] == "pi" for c in cs)


def test_module_for_service(archive):
    assert (
        archive.module_for_service(Service(port=22, service="ssh"))
        == "auxiliary/scanner/ssh/ssh_login"
    )
    assert (
        archive.module_for_service(Service(port=80, service="http"))
        == "auxiliary/scanner/http/http_login"
    )
    assert archive.module_for_service(Service(port=9999, service="weird")) is None


def test_smb_alias_matches(archive):
    # smb creds should apply to microsoft-ds / netbios-ssn too
    svc = Service(port=445, service="microsoft-ds")
    cs = archive.universal_for_service(svc)
    assert any(c["user"] == "administrator" for c in cs)


def test_archives_reload_on_missing(archive, monkeypatch, tmp_path):
    missing = tmp_path / "nope.json"
    monkeypatch.setattr(archive, "path", missing)
    archive.reload()
    assert archive.universal == []
    assert archive.vendors == []
