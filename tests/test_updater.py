# Tests for the periodic software-component updater (no network required).


from datetime import UTC

from services import updater


def test_should_run_when_no_state(tmp_path, monkeypatch):
    monkeypatch.setattr(updater, "UPDATER_STATE", tmp_path / "missing.json")
    assert updater.should_run() is True


def test_should_run_true_after_interval(tmp_path, monkeypatch):
    state = tmp_path / "last.json"
    monkeypatch.setattr(updater, "UPDATER_STATE", state)
    # write a state ~1 day old
    import json
    from datetime import datetime, timedelta

    old = datetime.now(UTC) - timedelta(days=1)
    state.write_text(json.dumps({"last": old.isoformat()}), encoding="utf-8")
    monkeypatch.setenv("H4K_UPDATE_INTERVAL", "3600")  # 1h
    assert updater.should_run() is True


def test_should_run_false_recent_state(tmp_path, monkeypatch):
    state = tmp_path / "last.json"
    monkeypatch.setattr(updater, "UPDATER_STATE", state)
    import json
    from datetime import datetime

    now = datetime.now(UTC)
    state.write_text(json.dumps({"last": now.isoformat()}), encoding="utf-8")
    monkeypatch.setenv("H4K_UPDATE_INTERVAL", "3600")
    assert updater.should_run() is False


def test_run_update_returns_report(tmp_path, monkeypatch):
    # Force tools to appear "not installed" so the run is fast and offline-safe.
    monkeypatch.setattr(updater, "_which", lambda t: None)
    res = updater.run_update()
    assert "tools" in res and "data" in res and "started" in res
    assert res["tools"]["semgrep"] == "not installed"
    assert res["tools"]["osv_scanner"] == "not installed"
    assert res["tools"]["trivy"] == "not installed"


def test_refresh_cve_data_best_effort_empty_env(tmp_path, monkeypatch):
    # ensure it doesn't crash even if services can't load
    res = updater.refresh_cve_data()
    assert "error" in res or "cve_db" in res
