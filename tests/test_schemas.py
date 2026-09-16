# Tests for the pydantic schemas.
from schemas import Host, Job, Report, ScanMode, ScanRequest, Service, Vuln


def test_scan_mode_is_strenum():
    assert ScanMode.overt.value == "overt"
    assert ScanMode.stealth == "stealth"
    assert ScanMode.tor == "tor"


def test_scan_request_defaults():
    req = ScanRequest(target="192.168.1.10")
    assert req.mode == ScanMode.overt
    assert req.do_dns_recon is True
    assert req.do_vuln_scan is True


def test_scan_request_validates_mode():
    req = ScanRequest(target="host.example", mode=ScanMode.stealth)
    assert req.mode == ScanMode.stealth


def test_service_defaults():
    svc = Service(port=22)
    assert svc.proto == "tcp"
    assert svc.service is None
    assert svc.state is None
    assert svc.info is None


def test_host_with_services():
    svc = Service(port=80, service="http", state="open")
    host = Host(address="10.0.0.5", os="Linux", services=[svc])
    assert host.services[0].port == 80
    assert host.os == "Linux"


def test_vuln_refs_coerced_by_hand():
    # The report layer normalizes string refs -> list; schema stays strict.
    v = Vuln(name="test", refs=["CVE-1"])
    assert v.refs == ["CVE-1"]


def test_job_optional_report():
    job = Job(id="abc", status="running", progress=50.0)
    assert job.report is None
    assert job.error is None


def test_report_aggregates():
    r = Report(
        target="t",
        mode=ScanMode.overt,
        created_at="2026-01-01T00:00:00Z",
        hosts=[],
        vulns=[],
        recommendations=[],
        notes=[],
    )
    assert r.mode == ScanMode.overt
