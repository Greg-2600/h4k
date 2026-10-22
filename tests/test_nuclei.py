# Tests for nuclei.py
from unittest.mock import MagicMock, patch

from h4k.api.services.nuclei import (
    NucleiRunner,
    NucleiService,
    _as_text,
    nuclei_scan,
)


class TestAsText:
    def test_none(self):
        assert _as_text(None) == ""

    def test_bytes(self):
        assert _as_text(b"hello") == "hello"

    def test_str(self):
        assert _as_text("hello") == "hello"


class TestNucleiServiceInit:
    def test_default_progress(self):
        svc = NucleiService()
        assert svc.progress is not None

    def test_custom_progress(self):
        calls = []

        def cb(msg, pct):
            calls.append((msg, pct))

        svc = NucleiService(progress=cb)
        svc.progress("test", 0.5)
        assert calls == [("test", 0.5)]


class TestNucleiServiceRun:
    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "nuclei output"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc._run(["nuclei", "-target", "http://example.com"])

        assert result["rc"] == 0
        assert result["success"] is True
        assert result["stdout"] == "nuclei output"

    @patch("subprocess.run")
    def test_run_failure(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = "error"
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc._run(["nuclei", "-target", "http://example.com"])

        assert result["success"] is False
        assert result["rc"] == 1

    @patch("subprocess.run")
    def test_run_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("nuclei", 300)

        svc = NucleiService()
        result = svc._run(["nuclei", "-target", "http://example.com"])

        assert result["timed_out"] is True
        assert result["success"] is False

    @patch("subprocess.run")
    def test_run_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        svc = NucleiService()
        result = svc._run(["nuclei", "-target", "http://example.com"])

        assert result["stderr"] == "nuclei not installed"
        assert result["success"] is False

    @patch("subprocess.run")
    def test_run_progress_called(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        calls = []

        def progress(msg, pct):
            calls.append((msg, pct))

        svc = NucleiService(progress=progress)
        svc._run(["nuclei", "-target", "http://example.com"])

        assert len(calls) == 1
        assert "nuclei" in calls[0][0]


class TestNucleiServiceScan:
    @patch("subprocess.run")
    def test_scan_basic(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.scan("http://example.com")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "nuclei" in argv
        assert "-target" in argv
        assert "http://example.com" in argv
        assert "-jsonl" in argv
        assert "-silent" in argv

    @patch("subprocess.run")
    def test_scan_with_templates(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan(
            "http://example.com", templates=["cves/CVE-2021-44228", "sql-injection"]
        )

        argv = mock_run.call_args[0][0]
        assert "-t" in argv
        assert "cves/CVE-2021-44228" in argv

    @patch("subprocess.run")
    def test_scan_with_severity(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan("http://example.com", severity="critical,high")

        argv = mock_run.call_args[0][0]
        assert "-severity" in argv
        assert "critical,high" in argv

    @patch("subprocess.run")
    def test_scan_with_tags(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan("http://example.com", tags=["rce", "sqli"])

        argv = mock_run.call_args[0][0]
        assert "-tags" in argv
        assert "rce" in argv

    @patch("subprocess.run")
    def test_scan_with_exclude_tags(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan("http://example.com", exclude_tags=["dos", "spam"])

        argv = mock_run.call_args[0][0]
        assert "-exclude-tags" in argv
        assert "dos" in argv

    @patch("subprocess.run")
    def test_scan_with_rate_limit(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan("http://example.com", rate_limit=100)

        argv = mock_run.call_args[0][0]
        assert "-rate-limit" in argv
        assert "100" in argv

    @patch("subprocess.run")
    def test_scan_verbose(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.scan("http://example.com", verbose=True)

        argv = mock_run.call_args[0][0]
        assert "-v" in argv

    @patch("subprocess.run")
    def test_scan_parses_jsonl(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = '{"info":{"severity":"critical","matched":"http://example.com"},"type":"http"}'
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.scan("http://example.com")

        assert len(result["findings"]) == 1
        assert result["findings"][0]["info"]["severity"] == "critical"
        assert result["finding_count"] == 1

    @patch("subprocess.run")
    def test_scan_handles_invalid_jsonl(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = '{"type":"a"}\nnot-json\n{"type":"b"}'
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.scan("http://example.com")

        assert len(result["findings"]) == 2


class TestNucleiServiceUpdateTemplates:
    @patch("subprocess.run")
    def test_update_templates(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "templates updated"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.update_templates()

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-update-templates" in argv


class TestNucleiServiceListTemplates:
    @patch("subprocess.run")
    def test_list_templates(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "template list"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.list_templates()

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-tl" in argv

    @patch("subprocess.run")
    def test_list_templates_with_tags(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        svc.list_templates(tags=["cve", "rce"])

        argv = mock_run.call_args[0][0]
        assert "-tags" in argv


class TestNucleiServiceValidateTemplates:
    @patch("subprocess.run")
    def test_validate_templates(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = NucleiService()
        result = svc.validate_templates(["/path/to/template.yaml"])

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-validate" in argv
        assert "-t" in argv


class TestNucleiRunner:
    @patch("subprocess.run")
    def test_full_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        runner = NucleiRunner()
        result = runner.full_scan("http://example.com")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-severity" in argv
        assert "critical,high,medium" in argv

    @patch("subprocess.run")
    def test_full_scan_with_exclude_tags(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        runner = NucleiRunner()
        runner.full_scan("http://example.com", exclude_tags=["dos"])

        argv = mock_run.call_args[0][0]
        assert "-exclude-tags" in argv

    @patch("subprocess.run")
    def test_cve_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        runner = NucleiRunner()
        runner.cve_scan("http://example.com", ["CVE-2021-44228", "CVE-2022-12345"])

        argv = mock_run.call_args[0][0]
        assert "-t" in argv
        assert "cves/CVE-2021-44228" in argv

    @patch("subprocess.run")
    def test_technology_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        runner = NucleiRunner()
        runner.technology_scan("http://example.com", tech=["wordpress", "apache"])

        argv = mock_run.call_args[0][0]
        assert "-tags" in argv


class TestNucleiScanConvenience:
    @patch("subprocess.run")
    def test_nuclei_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = nuclei_scan("http://example.com", severity="critical")

        assert result["rc"] == 0
