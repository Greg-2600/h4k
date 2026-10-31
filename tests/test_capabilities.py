"""Tests for the capability/readiness report.

The report is what an operator (and the UI badge) reads to find out what
will work and what will quietly fail, so the important part is that the
warnings are honest.
"""

from typing import ClassVar

from services.capabilities import (
    build_report,
    metasploit_report,
    storage_report,
    tool_report,
)


class FakeCore:
    version: ClassVar[dict] = {
        "version": "6.5.9-dev",
        "ruby": "3.4",
        "api": "1.0",
    }


class FakeMsf:
    """A Metasploit client that answers the calls the report makes."""

    def __init__(self, db_connected=True, modules=2700):
        self.db_connected = db_connected
        self._modules = modules

        class _Client:
            def __init__(self, outer):
                self.outer = outer
                self.core = FakeCore()

            def call(self, method, args=None):
                if method == "db.workspaces":
                    if self.outer.db_connected:
                        return {"workspaces": [{"id": 1, "name": "default"}]}
                    return {"error": True}
                return {}

        self.client = _Client(self)

    def list_modules(self, mtype):
        return ["exploit/x"] * self._modules if mtype == "exploit" else []


def test_tool_report_lists_every_known_tool():
    tools = tool_report()
    assert "nmap" in tools
    assert "hydra" in tools
    assert "semgrep" in tools
    for name, info in tools.items():
        assert "purpose" in info, name
        assert isinstance(info["installed"], bool)


def test_metasploit_report_detects_a_connected_database():
    report = metasploit_report(FakeMsf(db_connected=True))
    assert report["reachable"] is True
    assert report["database"] == "connected"
    assert report["modules"] == 2700


def test_metasploit_report_flags_a_missing_database():
    report = metasploit_report(FakeMsf(db_connected=False))
    assert report["reachable"] is True
    assert report["database"] == "not connected"


def test_metasploit_report_survives_a_dead_daemon():
    class Dead:
        @property
        def client(self):
            raise RuntimeError("msfrpcd is down")

    report = metasploit_report(Dead())
    assert report["reachable"] is False
    assert "error" in report


def test_storage_report_points_at_the_data_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    report = storage_report()
    assert report["data_dir"] == str(tmp_path)
    assert report["writable"] is True
    kinds = {w["kind"] for w in report["wordlists"]}
    assert {"users", "passwords", "web-words"} <= kinds


def test_build_report_warns_when_metasploit_has_no_database(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    report = build_report(FakeMsf(db_connected=False), use_cache=False)
    assert report["features"]["metasploit_exploitation"] is True
    assert report["features"]["metasploit_database"] is False
    assert any("database is not connected" in w for w in report["warnings"])


def test_build_report_flags_sandbox_mode(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("H4K_SANDBOX", "1")
    report = build_report(None, use_cache=False)
    assert report["sandbox"] is True
    assert any("sandbox" in w.lower() for w in report["warnings"])


def test_build_report_warns_when_metasploit_database_call_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))

    class RaisingMsf:
        @property
        def client(self):
            class _Client:
                core = FakeCore()

                def call(self, method, args=None):
                    raise RuntimeError("db gone")

            return _Client()

        def list_modules(self, mtype):
            return []

    report = build_report(RaisingMsf(), use_cache=False)
    assert report["metasploit"]["database"] == "not connected"
    assert "db_error" in report["metasploit"]


def test_build_report_warns_when_tools_are_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import services.capabilities as cap

    monkeypatch.setattr(cap.shutil, "which", lambda _name: None)
    report = build_report(None, use_cache=False, force=True)
    assert report["features"]["recon"] is False
    assert report["features"]["password_attacks"] is False
    assert report["features"]["static_analysis"] is False
    assert any("nmap is missing" in w for w in report["warnings"])
    assert any("hydra is missing" in w for w in report["warnings"])


def test_build_report_warns_when_storage_is_not_writable(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import paths as paths_mod

    monkeypatch.setattr(paths_mod, "is_writable", lambda _p: False)
    report = build_report(None, use_cache=False)
    assert any("data dir" in w and "not writable" in w for w in report["warnings"])


def test_build_report_shape(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    report = build_report(FakeMsf())
    for key in ("ok", "features", "warnings", "tools", "metasploit", "storage"):
        assert key in report
    assert isinstance(report["features"], dict)
    assert "recon" in report["features"]
