# Job status honesty: background runners must flip queued -> running up
# front. Without this the monitor reads "queued" for the whole run while
# progress advances underneath (seen live: "queued at 20%").
from types import SimpleNamespace

from schemas import ScanRequest


def test_run_fuzz_flips_to_running(monkeypatch):
    from routers import scan as scan_router

    seen = []

    class _FakeFuzzer:
        def __init__(self, *a, **k):
            self.stats = {}

        def _fuzz_http(self, host, port, scheme="http"):
            seen.append("x")
            assert job["status"] == "running"
            return []

    monkeypatch.setattr(scan_router, "LabFuzzer", None, raising=False)
    import services.fuzzer as fz

    monkeypatch.setattr(fz, "LabFuzzer", _FakeFuzzer)
    req = SimpleNamespace(iterations=5, timeout=1.0, scheme="http")
    job = {"id": "j", "status": "queued", "candidates": []}
    scan_router._run_fuzz(job, req, "127.0.0.1", 8080)
    assert seen == ["x"]
    assert job["status"] == "done"


def test_run_fuzz_keeps_pre_start_abort(monkeypatch):
    import services.fuzzer as fz
    from routers import scan as scan_router

    class _FakeFuzzer:
        def __init__(self, *a, **k):
            self.stats = {}

        def _fuzz_http(self, host, port, scheme="http"):
            assert job["status"] == "abort_requested"
            return []

    monkeypatch.setattr(fz, "LabFuzzer", _FakeFuzzer)
    req = SimpleNamespace(iterations=5, timeout=1.0, scheme="http")
    job = {"id": "j", "status": "abort_requested", "candidates": []}
    scan_router._run_fuzz(job, req, "127.0.0.1", 8080)
    assert (
        job["status"] == "done"
    )  # fuzz has no mid-run abort; guard only preserves intent


def test_run_scan_flips_to_running(monkeypatch):
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_get_msf", lambda: object())
    monkeypatch.setattr(scan_router, "_get_cve_db", lambda: None)

    seen = {}

    class _FakePipeline:
        def __init__(self, msf, progress=None, log=None, should_stop=None):
            pass

        def run(self, req):
            seen["status_at_run"] = job["status"]
            return {}

    monkeypatch.setattr(scan_router, "ScanPipeline", _FakePipeline)
    monkeypatch.setattr(
        scan_router,
        "build_report",
        lambda **k: SimpleNamespace(model_dump=lambda: {}),
    )
    req = ScanRequest(target="10.0.0.1")
    job = {"id": "j", "status": "queued", "log": []}
    scan_router._run_scan(job, req)
    assert seen["status_at_run"] == "running"
    assert job["status"] == "done"


def test_run_scan_keeps_pre_start_abort(monkeypatch):
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_get_msf", lambda: object())
    monkeypatch.setattr(scan_router, "_get_cve_db", lambda: None)

    seen = {}

    class _FakePipeline:
        def __init__(self, msf, progress=None, log=None, should_stop=None):
            self._stop = should_stop

        def run(self, req):
            seen["status_at_run"] = job["status"]
            assert self._stop() is True
            return {}

    monkeypatch.setattr(scan_router, "ScanPipeline", _FakePipeline)
    monkeypatch.setattr(
        scan_router,
        "build_report",
        lambda **k: SimpleNamespace(model_dump=lambda: {}),
    )
    req = ScanRequest(target="10.0.0.1")
    job = {"id": "j", "status": "abort_requested", "log": []}
    scan_router._run_scan(job, req)
    assert seen["status_at_run"] == "abort_requested"
