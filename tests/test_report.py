# Tests for report generation and recommendation scoring.
from schemas import Report
from services.report import _difficulty, _host_from_dict, build_report


def _cve_db():
    from pathlib import Path

    from services.cve_lookup import CveDb

    data = Path(__file__).resolve().parent.parent / "h4k" / "data" / "cves.json"
    return CveDb(data)


def test_build_report_empty():
    r = build_report(target="t", mode="overt", hosts=[], vulns=[], notes=[])
    assert r.target == "t"
    assert isinstance(r, Report)
    assert r.hosts == []
    assert r.recommendations == []


def test_build_report_host_shape():
    hosts = [
        {
            "address": "10.0.0.5",
            "os_name": "Linux",
            "state": "alive",
            "services": [{"port": 22, "service": "ssh", "state": "open"}],
        }
    ]
    r = build_report("10.0.0.5", "overt", hosts, [], [])
    assert r.hosts[0].address == "10.0.0.5"
    assert r.hosts[0].services[0].service == "ssh"


def test_build_report_with_cve_enrichment():
    hosts = [
        {
            "address": "10.0.0.5",
            "services": [{"port": 22, "service": "ssh", "info": "OpenSSH 9.2p1"}],
        }
    ]
    vulns = [
        {
            "name": "SSH Version Scanner",
            "port": 22,
            "refs": ["https://example/x#host-keys"],
        }
    ]
    r = build_report("10.0.0.5", "overt", hosts, vulns, [], cve_db=_cve_db())
    # SSH service should surface SSH-related CVEs as recommendations
    assert any("CVE-2015-5602" in (rec.refs or []) for rec in r.recommendations)


def test_build_report_deduplicates_cves():
    hosts = [
        {
            "address": "10.0.0.5",
            "services": [{"port": 22, "service": "ssh", "info": "OpenSSH"}],
        }
    ]
    r = build_report("10.0.0.5", "stealth", hosts, [], [], cve_db=_cve_db())
    cve_ids = [cve for rec in r.recommendations for cve in (rec.refs or [])]
    assert len(cve_ids) == len(set(cve_ids))


def test_difficulty_mapping():
    assert _difficulty(0) == "hard"
    assert _difficulty(3) == "hard"
    assert _difficulty(6) == "moderate"
    assert _difficulty(8) == "trivial"
    assert _difficulty(9) == "easy"
    # cvss * 10 inputs
    assert _difficulty(98) == "easy"


def test_host_from_dict_normalizes_services():
    h = _host_from_dict(
        {
            "address": "x",
            "services": [{"port": 80, "service": "http", "state": "open"}],
        }
    )
    assert h.services[0].port == 80


# --- port-scan coverage honesty --------------------------------------------
def test_report_carries_coverage():
    r = build_report(
        target="h",
        mode="overt",
        hosts=[],
        vulns=[],
        notes=[],
        coverage={
            "depth": "standard",
            "ports_spec": "top-1000",
            "max_ports": 1000,
            "complete": False,
        },
    )
    assert r.coverage is not None
    assert r.coverage.depth == "standard"
    assert r.coverage.complete is False


def test_partial_scan_is_flagged_in_notes():
    """A top-N sweep must never read as 'nothing found on this host'."""
    r = build_report(
        target="h",
        mode="overt",
        hosts=[],
        vulns=[],
        notes=[],
        coverage={
            "depth": "standard",
            "ports_spec": "top-1000",
            "max_ports": 1000,
            "complete": False,
        },
    )
    cov_notes = [n for n in r.notes if n.startswith("[coverage]")]
    assert cov_notes, r.notes
    assert "PARTIAL" in cov_notes[0]
    assert "top-1000" in cov_notes[0]
    assert "depth=full" in cov_notes[0]


def test_full_scan_produces_no_partial_warning():
    r = build_report(
        target="h",
        mode="overt",
        hosts=[],
        vulns=[],
        notes=[],
        coverage={
            "depth": "full",
            "ports_spec": "1-65535",
            "max_ports": 65535,
            "complete": True,
        },
    )
    assert not [n for n in r.notes if n.startswith("[coverage]")]


def test_report_without_coverage_has_no_warning():
    r = build_report(target="h", mode="overt", hosts=[], vulns=[], notes=[])
    assert r.coverage is None
    assert not [n for n in r.notes if n.startswith("[coverage]")]
