# Tests for security.py
from unittest.mock import MagicMock, patch

import pytest

from h4k.api.services.security import (
    SecurityAssessmentService,
    _confidence,
    _is_hop_line,
    _is_private_ip,
    _is_star,
    _level,
    _score,
)


class TestIsHopLine:
    @pytest.mark.parametrize(
        "line,expected",
        [
            (" 1  10.0.0.1", True),
            (" 10  192.168.1.1", True),
            ("12    1.2.3.4", True),
            ("", False),
            ("not a hop", False),
            ("0 1.2.3.4", True),
            ("  1", False),
        ],
    )
    def test_is_hop_line(self, line, expected):
        assert _is_hop_line(line) == expected


class TestIsStar:
    @pytest.mark.parametrize(
        "line,expected",
        [
            (" 1  * * *", True),
            (" 2  10.0.0.1", False),
            ("* * *", True),
            ("no star", False),
        ],
    )
    def test_is_star(self, line, expected):
        assert _is_star(line) == expected


class TestIsPrivateIp:
    @pytest.mark.parametrize(
        "line,expected",
        [
            (" 1  10.0.0.1", True),
            (" 1  172.16.0.1", True),
            (" 1  192.168.1.1", True),
            (" 1  8.8.8.8", False),
            (" 1  1.1.1.1", False),
            ("no ip here", False),
            (" 1  ::1", False),
        ],
    )
    def test_is_private_ip(self, line, expected):
        assert _is_private_ip(line) == expected


class TestScore:
    @pytest.mark.parametrize(
        "signals,min_score",
        [
            (["large-service-surface"], 70),
            (["moderate-service-surface"], 58),
            (["plaintext-mgmt"], 55),
            (["public-internet-path"], 60),
            (["minimal-service-surface"], 25),
            (["all-internal-path"], 30),
            (["many-star-hops"], 20),
            (["icmp-blocked-or-no-route"], 15),
            ([], 40),
            (["large-service-surface", "plaintext-mgmt", "public-internet-path"], 100),
            (["minimal-service-surface", "all-internal-path", "many-star-hops"], 0),
        ],
    )
    def test_score_bounds(self, signals, min_score):
        result = _score(signals)
        assert result >= min_score
        assert 0.0 <= result <= 100.0

    def test_score_caps_at_100(self):
        result = _score(
            [
                "large-service-surface",
                "plaintext-mgmt",
                "public-internet-path",
                "large-service-surface",
            ]
        )
        assert result <= 100.0


class TestLevel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (100, "low"),
            (70, "low"),
            (69, "medium"),
            (45, "medium"),
            (44, "high"),
            (0, "high"),
        ],
    )
    def test_level(self, score, expected):
        assert _level(score) == expected


class TestConfidence:
    @pytest.mark.parametrize(
        "signals,expected",
        [
            ([], "low"),
            (["a"], "low"),
            (["a", "b"], "medium"),
            (["a", "b", "c"], "medium"),
            (["a", "b", "c", "d"], "high"),
        ],
    )
    def test_confidence(self, signals, expected):
        assert _confidence(signals) == expected


class TestSecurityAssessmentServiceInit:
    def test_default_progress(self):
        svc = SecurityAssessmentService()
        assert svc.progress is not None

    def test_custom_progress(self):
        calls = []

        def progress(msg, pct):
            calls.append((msg, pct))

        svc = SecurityAssessmentService(progress=progress)
        svc.progress("test", 0.5)
        assert calls == [("test", 0.5)]


class TestSecurityAssessmentServiceTraceroute:
    @patch("subprocess.run")
    def test_traceroute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "traceroute output"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        svc = SecurityAssessmentService()
        result = svc.traceroute("8.8.8.8")

        assert result == "traceroute output"
        argv = mock_run.call_args[0][0]
        assert "traceroute" in argv
        assert "8.8.8.8" in argv

    @patch("subprocess.run")
    def test_traceroute_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        svc = SecurityAssessmentService()
        result = svc.traceroute("8.8.8.8")

        assert result == ""

    @patch("subprocess.run")
    def test_traceroute_uses_hops_param(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        svc = SecurityAssessmentService()
        svc.traceroute("8.8.8.8", hops=10)

        argv = mock_run.call_args[0][0]
        assert "-m" in argv
        assert "10" in argv


class TestSecurityAssessmentServiceAssess:
    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_no_route(self, mock_traceroute):
        mock_traceroute.return_value = ""

        svc = SecurityAssessmentService()
        result = svc.assess("10.0.0.1")

        assert result["host"] == "10.0.0.1"
        assert "icmp-blocked-or-no-route" in result["signals"]
        assert result["level"] == "high"

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_all_internal_path(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1\n 2  10.0.1.1\n 3  10.0.2.1\n"

        svc = SecurityAssessmentService()
        result = svc.assess("10.0.0.1")

        assert "all-internal-path" in result["signals"]
        assert result["level"] == "high"
        assert result["confidence"] == "low"

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_public_path(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1\n 2  172.217.1.1\n 3  8.8.8.8\n"

        svc = SecurityAssessmentService()
        result = svc.assess("10.0.0.1")

        assert "public-internet-path" in result["signals"]

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_many_stars(self, mock_traceroute):
        mock_traceroute.return_value = " 1  * * *\n 2  * * *\n 3  * * *\n 4  * * *\n"

        svc = SecurityAssessmentService()
        result = svc.assess("10.0.0.1")

        assert "many-star-hops" in result["signals"]

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_with_host_dict_minimal(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1"

        svc = SecurityAssessmentService()
        result = svc.assess(
            "10.0.0.1",
            host={"services": [{"state": "open", "service": "ssh"}]},
        )

        assert "minimal-service-surface" in result["signals"]

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_with_host_dict_moderate(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1"

        svc = SecurityAssessmentService()
        result = svc.assess(
            "10.0.0.1",
            host={
                "services": [
                    {"state": "open", "service": "ssh"},
                    {"state": "open", "service": "http"},
                    {"state": "closed", "service": "ftp"},
                    {"state": "open", "service": "https"},
                ]
            },
        )

        assert "moderate-service-surface" in result["signals"]

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_with_host_dict_large(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1"

        svc = SecurityAssessmentService()
        result = svc.assess(
            "10.0.0.1",
            host={
                "services": [
                    {"state": "open", "service": s}
                    for s in ["ssh", "http", "https", "telnet", "snmp", "ftp"]
                ]
            },
        )

        assert "large-service-surface" in result["signals"]

    @patch("h4k.api.services.security.SecurityAssessmentService.traceroute")
    def test_assess_plaintext_mgmt(self, mock_traceroute):
        mock_traceroute.return_value = " 1  10.0.0.1"

        svc = SecurityAssessmentService()
        result = svc.assess(
            "10.0.0.1",
            host={
                "services": [
                    {"state": "open", "service": "telnet"},
                    {"state": "open", "service": "snmp"},
                ]
            },
        )

        assert "plaintext-mgmt" in result["signals"]


class TestSecurityAssessmentServiceToDict:
    def test_to_dict(self):
        svc = SecurityAssessmentService()
        d = {"key": "value"}
        assert svc.to_dict(d) == d
