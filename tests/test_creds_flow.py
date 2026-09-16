# Tests for the opt-in default-credential attempt flow.
from services.scan_pipeline import ScanPipeline


class _FakeMsfNoLogin:
    """execute() never verifies a login (no valid creds)."""

    def __init__(self):
        self.calls = []

    def execute(self, mtype, mname, opts):
        self.calls.append((mtype, mname, dict(opts)))
        raise RuntimeError("auth failed")

    def current_workspace(self):
        return "default"

    def hosts(self, *a, **k):
        return []

    def services(self, *a, **k):
        return []


class _FakeMsfAlwaysLogin:
    """execute() always 'verifies' so attempts are recorded as verified."""

    def __init__(self):
        self.calls = []

    def execute(self, mtype, mname, opts):
        self.calls.append((mtype, mname, dict(opts)))
        return {"job_id": 1}

    def current_workspace(self):
        return "default"


def _hosts():
    return [
        {
            "address": "192.168.1.1",
            "os": None,
            "services": [{"port": 80, "service": "http", "state": "open"}],
        }
    ]


def test_creds_attempts_recorded_even_when_not_verified():
    msf = _FakeMsfNoLogin()
    fp = [{"host": "192.168.1.1", "vendor": "linksys", "technology": []}]
    pipe = ScanPipeline(msf)  # type: ignore[arg-type]
    creds = pipe._try_default_creds(_hosts(), fp, open_sessions=False)
    # universal http creds (admin/admin etc.) should have been attempted
    assert creds, "expected at least some cred attempts to be recorded"
    assert all(c["verified"] is False for c in creds)
    # http_login attempts carry a default URI
    any_http = [c for c in msf.calls if "http_login" in c[1]]
    assert any_http, "expected http_login attempts"
    assert all(o.get("URI") == "/" for _, _, o in any_http)


def test_creds_attempts_verified_flag():
    msf = _FakeMsfAlwaysLogin()
    fp = [{"host": "192.168.1.1", "vendor": "linksys", "technology": []}]
    pipe = ScanPipeline(msf)  # type: ignore[arg-type]
    creds = pipe._try_default_creds(_hosts(), fp, open_sessions=True)
    assert creds
    assert all(c["verified"] is True for c in creds)
