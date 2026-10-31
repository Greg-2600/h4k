# Provide the flat-import package root (h4k/api) on sys.path for tests.
import os
import sys
from pathlib import Path

import pytest

# tests/conftest.py -> repo root
REPO = Path(__file__).resolve().parent.parent
API_PKG = REPO / "h4k" / "api"
CVE_DATA = REPO / "h4k" / "data" / "cves.json"

# Put the package root first so `from schemas import ...` etc. resolve.
sys.path.insert(0, str(API_PKG))

# Tests run offline: don't attempt a network CVE refresh.
os.environ.setdefault("H4K_REFRESH_CVE", "0")


def pytest_collection_modifyitems(config, items):
    """Selenium E2E is opt-in: it needs a browser and starts a real API.

    `make test` stays fast and hermetic; `make e2e` (or H4K_E2E=1 pytest)
    runs the browser suite.
    """
    if os.environ.get("H4K_E2E") == "1":
        return
    skip_e2e = pytest.mark.skip(reason="Selenium E2E disabled (set H4K_E2E=1)")
    for item in items:
        if "e2e" in item.path.parts:
            item.add_marker(skip_e2e)


# shared fixture: fake the pipeline's subprocess boundary (msfconsole, dig...)
@pytest.fixture()
def no_subprocess(monkeypatch):
    """Pretend every subprocess the pipeline shells out to printed nothing."""
    import services.scan_pipeline as sp_mod

    canned: dict = {}

    def _fake_run(argv, **kwargs):
        key = argv[0] if argv else ""
        out = canned.get(key, "")
        return type(
            "P", (), {"returncode": 0, "stdout": out, "stderr": "", "check": False}
        )()

    monkeypatch.setattr(sp_mod.subprocess, "run", _fake_run)
    return canned


@pytest.fixture()
def clean_db(monkeypatch, tmp_path):
    """Isolated neighbors store per test."""
    from routers import scan as scan_router

    monkeypatch.setattr(scan_router, "_NEIGHBOR_DB", tmp_path / "neighbors.db")
    return scan_router
