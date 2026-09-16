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
