# Tests for the fingerprinting helpers in the scan pipeline.
from schemas import Service
from services.scan_pipeline import (
    _cred_vendor,
    _match_hints,
    _match_hints_many,
    _service_from_dict,
)

HINTS = [("linksys", "linksys"), ("cisco", "cisco"), ("d-link", "dlink")]


def test_match_hints_first():
    assert _match_hints("linksys wrt54g http", HINTS) == "linksys"


def test_match_hints_no_match():
    assert _match_hints("unknown vendor", HINTS) == ""


def test_match_hints_many():
    out = _match_hints_many("linksys cisco d-link", HINTS)
    assert out == ["linksys", "cisco", "dlink"]


def test_match_hints_many_dedups():
    out = _match_hints_many("linksys linksys cisco", HINTS)
    assert out == ["linksys", "cisco"]


def test_cred_vendor_uses_fingerprint():
    fp = {"vendor": "linksys"}
    assert _cred_vendor(fp, [], {}) == "linksys"


def test_cred_vendor_falls_back_to_cred():
    assert _cred_vendor({}, [], {"vendor": "arris"}) == "arris"
    assert _cred_vendor({}, [], {}) == "common"


def test_service_from_dict():
    svc = _service_from_dict(
        {
            "port": 22,
            "proto": "tcp",
            "service": "ssh",
            "state": "open",
            "info": "OpenSSH",
        }
    )
    assert isinstance(svc, Service)
    assert svc.port == 22
    assert svc.service == "ssh"


NMAP_SV_XML = """<?xml version="1.0"?>
<nmaprun><host starttime="1"><status state="up"/>
<address addr="192.168.1.84" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="10.2p1" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.27.2" method="probed" conf="10"/></port>
<port protocol="tcp" portid="21"><state state="closed"/><service name="ftp" method="table" conf="3"/></port>
</ports></host></nmaprun>"""


def test_parse_nmap_xml_keeps_versions_and_products():
    """Recon quality gate: -sV versions must survive parsing, or the
    banner-aware CVE matcher downstream sees nothing and reports no vulns."""
    from routers.scan import _parse_nmap_xml

    entries = _parse_nmap_xml(NMAP_SV_XML)
    assert len(entries) == 1
    svcs = {s["port"]: s for s in entries[0]["services"]}
    assert svcs[22]["state"] == "open"
    assert svcs[22]["product"] == "OpenSSH"
    assert svcs[22]["version"] == "10.2p1"
    assert svcs[80]["product"] == "nginx"
    assert svcs[80]["version"] == "1.27.2"
    assert svcs[21]["state"] == "closed"
