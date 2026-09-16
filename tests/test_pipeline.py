# Tests for pure helper logic in the scan pipeline.

from services.scan_pipeline import (
    ScanPipeline,
    _is_ip,
    _looks_like_domain,
    _target_matches,
)


def test_normalize_ip():
    assert ScanPipeline.normalize_target("192.168.1.5") == "192.168.1.5"


def test_normalize_cidr() -> None:
    assert ScanPipeline.normalize_target("10.0.0.0/24") == "10.0.0.0/24"


def test_normalize_hostname():
    assert ScanPipeline.normalize_target("example.com") == "example.com"


def test_normalize_invalid_ip_passthrough():
    # unparseable but no slash -> treated as hostname string
    assert ScanPipeline.normalize_target("weird!@#") == "weird!@#"


def test_is_ip():
    assert _is_ip("192.168.0.1") is True
    assert _is_ip("not-an-ip") is False


def test_looks_like_domain():
    assert _looks_like_domain("example.com") is True
    assert _looks_like_domain("192.168.0.1") is False
    assert _looks_like_domain("10.0.0.0/24") is False
    assert _looks_like_domain("weird") is False


def test_target_matches_single_ip():
    assert _target_matches("10.0.0.9", "10.0.0.9") is True
    assert _target_matches("10.0.0.10", "10.0.0.9") is False


def test_target_matches_cidr():
    assert _target_matches("10.0.0.5", "10.0.0.0/24") is True
    assert _target_matches("10.0.1.5", "10.0.0.0/24") is False


def test_target_matches_none():
    assert _target_matches(None, "10.0.0.0/24") is False
