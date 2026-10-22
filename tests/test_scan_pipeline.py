# Tests for scan_pipeline.py module-level helpers and ScanPipeline class.
from unittest.mock import MagicMock

import pytest

from h4k.api.services.scan_pipeline import (
    ScanPipeline,
    _cred_vendor,
    _is_ip,
    _looks_like_domain,
    _match_hints,
    _match_hints_many,
    _service_from_dict,
    _target_matches,
)

# ---------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------


class TestIsIp:
    @pytest.mark.parametrize(
        "addr,expected",
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("::1", True),
            ("8.8.8.8", True),
            ("not.an.ip", False),
            ("256.256.256.256", False),
            ("", False),
        ],
    )
    def test_is_ip(self, addr, expected):
        assert _is_ip(addr) == expected


class TestLooksLikeDomain:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("example.com", True),
            ("foo.bar.baz", True),
            ("10.0.0.1", False),
            ("192.168.1.0/24", False),
            ("not a domain", False),
            ("localhost", False),
        ],
    )
    def test_looks_like_domain(self, value, expected):
        assert _looks_like_domain(value) == expected


class TestTargetMatches:
    def test_matches_exact_ip(self):
        assert _target_matches("10.0.0.1", "10.0.0.1") is True

    def test_matches_ip_in_cidr(self):
        assert _target_matches("10.0.0.5", "10.0.0.0/24") is True

    def test_no_match_different_ip(self):
        assert _target_matches("10.0.0.1", "192.168.1.0/24") is False

    def test_no_match_none_addr(self):
        assert _target_matches(None, "10.0.0.0/24") is False

    def test_matches_hostname(self):
        assert _target_matches("host", "host") is True


class TestMatchHints:
    def test_returns_first_match(self):
        hints = [("win", "windows"), ("linux", "linux"), ("ubuntu", "debian")]
        assert _match_hints("this is a Windows server", hints) == "windows"

    def test_returns_empty_on_no_match(self):
        hints = [("win", "windows"), ("linux", "linux")]
        assert _match_hints("solaris box", hints) == ""

    def test_returns_all_matches(self):
        hints = [("win", "windows"), ("server", "windows"), ("linux", "linux")]
        result = _match_hints("Windows Linux server", hints, all_matches=True)
        assert result == ["windows", "linux"]

    def test_match_hints_case_insensitive(self):
        hints = [("WINDOWS", "windows"), ("Linux", "linux")]
        assert _match_hints("WINDOWS server", hints) == "windows"

    def test_match_hints_many_unique(self):
        hints = [("win", "windows"), ("server", "windows"), ("linux", "linux")]
        result = _match_hints_many("Windows server Linux", hints)
        assert result == ["windows", "linux"]

    def test_match_hints_many_empty(self):
        hints = [("win", "windows")]
        assert _match_hints_many("linux", hints) == []


class TestCredVendor:
    def test_uses_fp_vendor(self):
        fp = {"vendor": "Cisco"}
        assert _cred_vendor(fp, [], {}) == "Cisco"

    def test_falls_back_to_cred_vendor(self):
        fp = {}
        cred = {"vendor": "Juniper"}
        assert _cred_vendor(fp, [], cred) == "Juniper"

    def test_falls_back_to_common(self):
        fp = {}
        cred = {}
        assert _cred_vendor(fp, [], cred) == "common"


class TestServiceFromDict:
    def test_basic_fields(self):
        s = _service_from_dict({"port": 80, "proto": "tcp", "service": "http"})
        assert s.port == 80
        assert s.proto == "tcp"
        assert s.service == "http"

    def test_defaults(self):
        s = _service_from_dict({})
        assert s.port == 0
        assert s.proto == "tcp"
        assert s.service is None

    def test_with_info(self):
        s = _service_from_dict({"port": 443, "service": "https", "info": "Apache 2.4"})
        assert s.info == "Apache 2.4"


# ---------------------------------------------------------------------
# ScanPipeline class
# ---------------------------------------------------------------------


class TestScanPipelineInit:
    def test_init(self):
        mock_msf = MagicMock()
        pipeline = ScanPipeline(mock_msf)
        assert pipeline.msf is mock_msf
        assert pipeline.progress is not None
        assert pipeline._log is not None
        assert pipeline._should_stop is not None

    def test_custom_progress(self):
        mock_msf = MagicMock()
        calls = []

        def progress(msg, pct):
            calls.append((msg, pct))

        pipeline = ScanPipeline(mock_msf, progress=progress)
        pipeline.progress("hello", 0.5)
        assert calls == [("hello", 0.5)]

    def test_custom_log(self):
        mock_msf = MagicMock()
        logs = []

        def log_fn(msg):
            logs.append(msg)

        pipeline = ScanPipeline(mock_msf, log=log_fn)
        pipeline._log("message")
        assert logs == ["message"]

    def test_custom_should_stop(self):
        mock_msf = MagicMock()
        pipeline = ScanPipeline(mock_msf, should_stop=lambda: True)
        assert pipeline._should_stop() is True


class TestScanPipelineTick:
    def test_tick_calls_all(self):
        mock_msf = MagicMock()
        progress_calls = []
        log_calls = []

        pipeline = ScanPipeline(
            mock_msf,
            progress=lambda m, p: progress_calls.append((m, p)),
            log=lambda m: log_calls.append(m),
        )
        pipeline._tick("test message", 42.0)

        assert progress_calls == [("test message", 42.0)]
        assert log_calls == ["test message"]


class TestScanPipelineCheckAbort:
    def test_returns_false_when_not_stopped(self):
        mock_msf = MagicMock()
        pipeline = ScanPipeline(mock_msf, should_stop=lambda: False)
        assert pipeline._check_abort() is False

    def test_returns_true_and_logs_when_stopped(self):
        mock_msf = MagicMock()
        logs = []
        pipeline = ScanPipeline(
            mock_msf, should_stop=lambda: True, log=lambda m: logs.append(m)
        )
        assert pipeline._check_abort() is True
        assert any("abort" in log for log in logs)


class TestNormalizeTarget:
    def test_bare_ipv4(self):
        assert ScanPipeline.normalize_target("192.168.1.1") == "192.168.1.1"

    def test_bare_ipv6(self):
        assert ScanPipeline.normalize_target("::1") == "::1"

    def test_cidr_network(self):
        assert ScanPipeline.normalize_target("10.0.0.0/24") == "10.0.0.0/24"

    def test_hostname_passed_through(self):
        assert ScanPipeline.normalize_target("example.com") == "example.com"

    def test_invalid_ip_returns_as_is(self):
        result = ScanPipeline.normalize_target("not-an-ip")
        assert result == "not-an-ip"
