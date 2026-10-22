# Tests for sqlmap.py
from unittest.mock import MagicMock, patch

from h4k.api.services.sqlmap import (
    SQLMapRunner,
    SQLMapService,
    _as_text,
    sqlmap_scan,
)


class TestAsText:
    def test_none(self):
        assert _as_text(None) == ""

    def test_bytes(self):
        assert _as_text(b"hello") == "hello"

    def test_bytes_with_error(self):
        assert _as_text(b"\xff\xfe") == "��"

    def test_str(self):
        assert _as_text("hello") == "hello"


class TestSQLMapServiceInit:
    def test_default_progress(self):
        svc = SQLMapService()
        assert svc.progress is not None
        svc.progress("test", 0.5)

    def test_custom_progress(self):
        calls = []

        def cb(msg, pct):
            calls.append((msg, pct))

        svc = SQLMapService(progress=cb)
        svc.progress("test", 0.5)
        assert calls == [("test", 0.5)]


class TestSQLMapServiceRun:
    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "sqlmap output"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc._run(["sqlmap", "-u", "http://example.com"])

        assert result["rc"] == 0
        assert result["success"] is True
        assert result["stdout"] == "sqlmap output"

    @patch("subprocess.run")
    def test_run_failure(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "error"
        mock_proc.stderr = "failed"
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc._run(["sqlmap", "-u", "http://example.com"])

        assert result["success"] is False
        assert result["rc"] == 1

    @patch("subprocess.run")
    def test_run_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("sqlmap", 300)

        svc = SQLMapService()
        result = svc._run(["sqlmap", "-u", "http://example.com"])

        assert result["timed_out"] is True
        assert result["success"] is False

    @patch("subprocess.run")
    def test_run_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        svc = SQLMapService()
        result = svc._run(["sqlmap", "-u", "http://example.com"])

        assert result["stderr"] == "sqlmap not installed"
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

        svc = SQLMapService(progress=progress)
        svc._run(["sqlmap", "-u", "http://example.com"])

        assert len(calls) == 1
        assert "sqlmap" in calls[0][0]


class TestSQLMapServiceScan:
    @patch("subprocess.run")
    def test_scan_get_request(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "http://example.com is SQL injection vulnerable"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.scan("http://example.com")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "sqlmap" in argv
        assert "-u" in argv
        assert "http://example.com" in argv

    @patch("subprocess.run")
    def test_scan_with_method_and_data(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", method="POST", data="q=1")

        argv = mock_run.call_args[0][0]
        assert "--method" in argv
        assert "POST" in argv
        assert "--data" in argv
        assert "q=1" in argv

    @patch("subprocess.run")
    def test_scan_with_param(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", param="id")

        argv = mock_run.call_args[0][0]
        assert "-p" in argv
        assert "id" in argv

    @patch("subprocess.run")
    def test_scan_with_cookie(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", cookie="PHPSESSID=abc123")

        argv = mock_run.call_args[0][0]
        assert "--cookie" in argv
        assert "PHPSESSID=abc123" in argv

    @patch("subprocess.run")
    def test_scan_with_headers(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", headers={"Authorization": "Bearer token"})

        argv = mock_run.call_args[0][0]
        assert "-H" in argv
        assert "Authorization: Bearer token" in argv

    @patch("subprocess.run")
    def test_scan_with_level_and_risk(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", level=3, risk=2)

        argv = mock_run.call_args[0][0]
        assert "--level" in argv
        assert "3" in argv
        assert "--risk" in argv
        assert "2" in argv

    @patch("subprocess.run")
    def test_scan_with_technique(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", technique="BEUSTQ")

        argv = mock_run.call_args[0][0]
        assert "--technique" in argv
        assert "BEUSTQ" in argv

    @patch("subprocess.run")
    def test_scan_with_dbms(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", dbms="MySQL")

        argv = mock_run.call_args[0][0]
        assert "--dbms" in argv
        assert "MySQL" in argv

    @patch("subprocess.run")
    def test_scan_with_crawl(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", crawl=2)

        argv = mock_run.call_args[0][0]
        assert "--crawl" in argv
        assert "2" in argv

    @patch("subprocess.run")
    def test_scan_with_threads(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", threads=4)

        argv = mock_run.call_args[0][0]
        assert "--threads" in argv
        assert "4" in argv

    @patch("subprocess.run")
    def test_scan_with_output_dir(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", output_dir="/tmp/results")

        argv = mock_run.call_args[0][0]
        assert "--output-dir" in argv
        assert "/tmp/results" in argv

    @patch("subprocess.run")
    def test_scan_batch_default(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com")

        argv = mock_run.call_args[0][0]
        assert "--batch" in argv

    @patch("subprocess.run")
    def test_scan_no_batch(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.scan("http://example.com", batch=False)

        argv = mock_run.call_args[0][0]
        assert "--batch" not in argv

    @patch("subprocess.run")
    def test_scan_parses_findings(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "http://example.com is vulnerable to SQL injection"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.scan("http://example.com")

        assert len(result["findings"]) >= 1
        assert result["findings"][0]["type"] == "sqli"

    @patch("subprocess.run")
    def test_scan_no_findings(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "nothing found"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.scan("http://example.com")

        assert result["findings"] == []


class TestSQLMapServiceDumpTables:
    @patch("subprocess.run")
    def test_dump_tables_basic(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "dump output"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.dump_tables("http://example.com")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "--dump" in argv
        assert "--batch" in argv

    @patch("subprocess.run")
    def test_dump_tables_with_database(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.dump_tables("http://example.com", database="myapp")

        argv = mock_run.call_args[0][0]
        assert "-D" in argv
        assert "myapp" in argv

    @patch("subprocess.run")
    def test_dump_tables_with_tables(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        svc.dump_tables(
            "http://example.com", database="myapp", tables=["users", "posts"]
        )

        argv = mock_run.call_args[0][0]
        assert "-T" in argv
        assert "users,posts" in argv


class TestSQLMapServiceGetDatabases:
    @patch("subprocess.run")
    def test_get_databases(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "available databases: myapp, testdb"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.get_databases("http://example.com")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "--dbs" in argv


class TestSQLMapServiceGetTables:
    @patch("subprocess.run")
    def test_get_tables(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "tables listed"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.get_tables("http://example.com", "myapp")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-D" in argv
        assert "myapp" in argv
        assert "--tables" in argv


class TestSQLMapServiceGetColumns:
    @patch("subprocess.run")
    def test_get_columns(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "columns listed"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        svc = SQLMapService()
        result = svc.get_columns("http://example.com", "myapp", "users")

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-D" in argv
        assert "-T" in argv
        assert "--columns" in argv


class TestSQLMapRunner:
    @patch("subprocess.run")
    def test_full_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "scan complete"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        calls = []

        def progress(msg, pct):
            calls.append((msg, pct))

        runner = SQLMapRunner(progress=progress)
        result = runner.full_scan("http://example.com")

        assert result["rc"] == 0
        assert len(calls) == 3
        assert "Starting full SQLi scan" in calls[0][0]
        assert "completed" in calls[2][0]

        argv = mock_run.call_args[0][0]
        assert "--level" in argv
        assert "3" in argv

    @patch("subprocess.run")
    def test_blind_sqli_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        runner = SQLMapRunner()
        runner.blind_sqli_scan("http://example.com", param="id")

        argv = mock_run.call_args[0][0]
        assert "--technique" in argv
        assert "BEUSTQ" in argv


class TestSqlmapScanConvenience:
    @patch("subprocess.run")
    def test_sqlmap_scan(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        result = sqlmap_scan("http://example.com", level=2)

        assert result["rc"] == 0
        argv = mock_run.call_args[0][0]
        assert "-u" in argv
