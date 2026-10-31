"""Selenium end-to-end fixtures: a real browser against a real h4k API.

The API runs in **sandbox mode** (`H4K_SANDBOX=1`): nmap/hydra/Metasploit are
replaced by deterministic stand-ins, so the suite never touches a network and
always sees the same lab estate. Everything above the tool boundary -- the
API, the parsers, the engagement store, the attack-path engine, the UI -- is
the real thing.

Run with:  make e2e      (or: H4K_E2E=1 pytest tests/e2e -v)
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
API_PKG = REPO / "h4k" / "api"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class ApiClient:
    """Tiny JSON HTTP client (no extra dependency)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, path: str, payload=None):
        url = f"{self.base_url}{path}"
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode()
                return resp.status, (json.loads(body) if body else {})
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            try:
                return exc.code, json.loads(body) if body else {}
            except json.JSONDecodeError:
                return exc.code, {"detail": body}

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, payload=None):
        return self.request("POST", path, payload if payload is not None else {})

    def delete(self, path):
        return self.request("DELETE", path)


@pytest.fixture(scope="session")
def api_server(tmp_path_factory):
    """Start the h4k API in sandbox mode on a free port."""
    port = _free_port()
    data_dir = tmp_path_factory.mktemp("h4k-e2e-data")
    # Log to a file, never a pipe: an unread pipe fills up and wedges the API.
    log_path = data_dir / "api.log"
    log_file = open(log_path, "w", encoding="utf-8")  # noqa: SIM115 - closed below
    env = dict(os.environ)
    env.update(
        {
            "H4K_SANDBOX": "1",
            "H4K_DATA_DIR": str(data_dir),
            "H4K_REFRESH_CVE": "0",
            "H4K_AUTO_UPDATE": "0",
            "H4K_AUTO_SCAN": "0",
            "H4K_CVE_WEEKLY": "0",
            "H4K_LOG_LEVEL": "WARNING",
            "PYTHONUNBUFFERED": "1",
            # The whole suite hammers one sandbox server from one IP; the
            # production 600 req/min budget is a real limit the browser
            # suite must not trip over (throttling itself is covered by
            # tests/test_coverage_wave.py::test_rate_limit_429).
            "H4K_RATE_LIMIT": "100000",
        }
    )
    env["PYTHONPATH"] = os.pathsep.join(
        [str(API_PKG), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(API_PKG),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    client = ApiClient(base_url)
    deadline = time.time() + 60
    ready = False
    while time.time() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"h4k API died on startup:\n{out}")
        try:
            status, _ = client.get("/api/health")
            if status == 200:
                ready = True
                break
        except Exception:
            pass
        time.sleep(0.25)
    if not ready:
        proc.terminate()
        log_file.close()
        raise RuntimeError(
            f"h4k API did not become healthy in time; log:\n{log_path.read_text()[-2000:]}"
        )
    try:
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_file.close()


@pytest.fixture(scope="session")
def api(api_server):
    return ApiClient(api_server)


@pytest.fixture(scope="session")
def driver():
    """Headless Chromium, shared across the session for speed."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1600,1200")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-search-engine-choice-screen")
    # surface browser console output so the suite can fail on JS errors
    options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    # Chrome/Chromium and chromedriver: override for CI images that ship
    # Google Chrome instead of the Arch/Debian chromium packages.
    binary = os.environ.get("H4K_CHROME_BINARY", "").strip()
    if binary:
        options.binary_location = binary
    driver_path = os.environ.get("H4K_CHROMEDRIVER", "").strip()
    if not driver_path and Path("/usr/bin/chromedriver").exists():
        driver_path = "/usr/bin/chromedriver"

    service = Service(executable_path=driver_path) if driver_path else Service()

    drv = webdriver.Chrome(options=options, service=service)
    drv.set_page_load_timeout(60)
    try:
        yield drv
    finally:
        drv.quit()


@pytest.fixture()
def page(driver, api_server):
    """A fresh page per test (clean storage, clean URL).

    After the test, the browser console is inspected: an uncaught JavaScript
    error fails the test. That is what caught the Report page's missing
    `renderReportPreview()` (a ReferenceError on every page switch).
    """
    drv = driver
    drv.get("about:blank")
    try:
        # Never let a stale bundle survive between tests: the UI is served
        # with a cache-busting query string, but the browser may still hold
        # the previous response.
        drv.execute_cdp_cmd("Network.clearBrowserCache", {})
        drv.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})
        drv.execute_script(
            "window.localStorage.clear(); window.sessionStorage.clear();"
        )
    except Exception:
        pass
    with suppress(Exception):
        drv.get_log("browser")
    drv.get(api_server)
    yield drv
    errors = []
    try:
        for entry in drv.get_log("browser"):
            if entry.get("level") != "SEVERE":
                continue
            msg = entry.get("message", "")
            source = entry.get("source", "")
            # favicon 404s and autoplay warnings are noise, not bugs
            if "favicon" in msg or "AudioContext" in msg:
                continue
            if source == "network":
                # 4xx is a deliberate error path in some tests; 5xx is a bug
                if "status of 4" in msg:
                    continue
                errors.append(msg)
                continue
            errors.append(msg)
    except Exception:
        pass
    if errors:
        raise AssertionError("browser console errors:\n" + "\n".join(errors))


@pytest.fixture()
def seeded(api, page, api_server):
    """A sandbox engagement with hosts, credentials, and a crown jewel.

    The page is reloaded afterwards so the console picks up the new
    engagement (scope selector, badges) instead of the pre-seed state.

    The scope is cleared on teardown: the API process is shared by the whole
    session, and a test that expects "no active engagement" must not inherit
    one from the test before it.
    """
    status, payload = api.post("/api/engagement/sandbox-seed")
    assert status == 200, payload
    eng = payload["engagement"]
    api.post("/api/session/scope", {"engagement_id": eng["id"]})
    page.get(api_server)
    try:
        yield eng
    finally:
        api.post("/api/session/scope", {"engagement_id": None})
