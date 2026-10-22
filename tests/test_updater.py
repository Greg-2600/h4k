# Tests for updater.py
import json
from unittest.mock import MagicMock, patch

from h4k.api.services.updater import (
    _persist_state,
    _run,
    _which,
    refresh_tools,
    run_update,
    should_run,
)


class TestRun:
    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = "output"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        rc, out = _run(["echo", "hello"])
        assert rc == 0
        assert "output" in out

    @patch("subprocess.run")
    def test_run_failure(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = "error"
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        rc, out = _run(["false"])
        assert rc == 1
        assert "error" in out

    @patch("subprocess.run")
    def test_run_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()

        rc, out = _run(["nonexistent"])
        assert rc == -1
        assert "not installed" in out

    @patch("subprocess.run")
    def test_run_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 300)

        rc, out = _run(["sleep", "10"])
        assert rc == -1
        assert "timed out" in out


class TestWhich:
    @patch("shutil.which")
    def test_found(self, mock_which):
        mock_which.return_value = "/usr/bin/python3"

        result = _which("python3")
        assert result == "/usr/bin/python3"

    @patch("shutil.which")
    def test_not_found(self, mock_which):
        mock_which.return_value = None

        result = _which("nonexistent_tool_xyz")
        assert result is None


class TestRefreshTools:
    @patch("h4k.api.services.updater._which")
    def test_refresh_tools_semgrep_not_installed(self, mock_which):
        mock_which.return_value = None

        result = refresh_tools()

        assert result["semgrep"] == "not installed"

    @patch("h4k.api.services.updater._which")
    @patch("h4k.api.services.updater._run")
    def test_refresh_tools_semgrep_upgrade_fails(self, mock_run, mock_which):
        mock_which.return_value = "/usr/bin/semgrep"
        mock_run.return_value = (1, "install failed")

        result = refresh_tools()

        assert result["semgrep_upgrade_rc"] == 1

    @patch("h4k.api.services.updater._which")
    def test_refresh_tools_osv_not_installed(self, mock_which):
        def which_side_effect(tool):
            if tool == "semgrep":
                return "/usr/bin/semgrep"
            return None

        mock_which.side_effect = which_side_effect

        result = refresh_tools()

        assert result["osv_scanner"] == "not installed"

    @patch("h4k.api.services.updater._which")
    def test_refresh_tools_trivy_not_installed(self, mock_which):
        def which_side_effect(tool):
            if tool == "semgrep":
                return "/usr/bin/semgrep"
            if tool == "osv-scanner":
                return "/usr/bin/osv-scanner"
            return None

        mock_which.side_effect = which_side_effect

        result = refresh_tools()

        assert result["trivy"] == "not installed"


class TestPersistState:
    @patch("h4k.api.services.updater.UPDATER_STATE")
    def test_persists_state(self, mock_state):
        mock_path = MagicMock()
        mock_state.parent = mock_path
        mock_path.mkdir = MagicMock()
        mock_state.write_text = MagicMock()

        result = {
            "started": "2024-01-01T00:00:00Z",
            "finished": "2024-01-01T00:01:00Z",
            "tools": {},
            "data": {},
        }
        _persist_state(result)

        mock_state.write_text.assert_called_once()

    @patch("h4k.api.services.updater.UPDATER_STATE")
    def test_persist_state_handles_error(self, mock_state):
        mock_state.parent = MagicMock()
        mock_state.parent.mkdir.side_effect = OSError("read-only")

        result = {"finished": "2024-01-01T00:01:00Z"}
        _persist_state(result)


class TestShouldRun:
    @patch("h4k.api.services.updater.UPDATER_STATE")
    def test_should_run_no_file(self, mock_state):
        mock_state.read_text.side_effect = FileNotFoundError()

        assert should_run() is True

    @patch("h4k.api.services.updater.UPDATER_STATE")
    def test_should_run_invalid_json(self, mock_state):
        mock_state.read_text.return_value = "not json"

        assert should_run() is True

    @patch("h4k.api.services.updater.UPDATER_STATE")
    @patch.dict("os.environ", {}, clear=True)
    def test_should_run_empty_last(self, mock_state):
        mock_state.read_text.return_value = '{"last": ""}'

        assert should_run() is True

    @patch("h4k.api.services.updater.UPDATER_STATE")
    @patch.dict("os.environ", {}, clear=True)
    def test_should_run_within_interval(self, mock_state):
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        recent = (now - timedelta(hours=1)).isoformat()
        mock_state.read_text.return_value = json.dumps({"last": recent})

        assert should_run() is False

    @patch("h4k.api.services.updater.UPDATER_STATE")
    @patch.dict("os.environ", {"H4K_UPDATE_INTERVAL": "1"}, clear=True)
    def test_should_run_custom_interval(self, mock_state):
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        recent = (now - timedelta(seconds=30)).isoformat()
        mock_state.read_text.return_value = json.dumps({"last": recent})

        assert should_run() is True

    @patch("h4k.api.services.updater.UPDATER_STATE")
    @patch.dict("os.environ", {}, clear=True)
    def test_should_run_after_interval(self, mock_state):
        from datetime import UTC, datetime, timedelta

        now = datetime.now(UTC)
        old = (now - timedelta(hours=10)).isoformat()
        mock_state.read_text.return_value = json.dumps({"last": old})

        assert should_run() is True


class TestRunUpdate:
    @patch("h4k.api.services.updater._persist_state")
    @patch("h4k.api.services.updater.refresh_cve_data")
    @patch("h4k.api.services.updater.refresh_tools")
    def test_run_update(self, mock_tools, mock_data, mock_persist):
        mock_tools.return_value = {"semgrep": "ok"}
        mock_data.return_value = {"cve_db": {"before": 10, "after": 10}}

        result = run_update()

        assert "started" in result
        assert "finished" in result
        assert "tools" in result
        assert "data" in result
        mock_persist.assert_called_once()
