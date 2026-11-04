# LIVE flow test: full recon pass against a real LAN target you own.
#
# Opt-in and excluded from CI: set H4K_LIVE_E2E=1 (and optionally
# H4K_LIVE_URL, H4K_LIVE_TARGET) to run against a real deployment.
# Recon ONLY -- scan + fingerprint + vuln correlation. No credential
# testing, no exploitation, nothing aggressive. A temporary scoped
# engagement is created for fingerprint scope checks and deleted after.
import json
import os
import time
import urllib.request

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("H4K_LIVE_E2E") != "1",
    reason="live-target test (set H4K_LIVE_E2E=1 to run)",
)

LIVE_URL = os.environ.get("H4K_LIVE_URL", "http://127.0.0.1:3137").rstrip("/")
TARGET = os.environ.get("H4K_LIVE_TARGET", "192.168.1.84")


def _api(method, path, payload=None):
    url = LIVE_URL + path
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _wait_until(predicate, timeout, interval=10, label="condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {label}; last={last!r}")


@pytest.fixture(scope="module")
def scoped_engagement():
    status, eng = _api(
        "POST",
        "/api/engagement",
        {"name": "e2e-live", "scope": [f"{TARGET}/32"]},
    )
    assert status == 200, eng
    eng_id = eng["id"]
    status, _ = _api("POST", "/api/session/scope", {"engagement_id": eng_id})
    assert status == 200
    try:
        yield eng_id
    finally:
        _api("POST", "/api/session/scope", {"engagement_id": None})
        _api("DELETE", f"/api/engagement/{eng_id}")


def test_live_scan_status_transitions(scoped_engagement):
    """The reported bug: polled status must flip queued -> running."""
    status, body = _api(
        "POST",
        "/api/scan",
        {"target": TARGET, "mode": "overt", "do_dns_recon": False},
    )
    assert status == 200, body
    job_id = body.get("id") or body.get("job_id")
    assert job_id

    samples = []

    def _poll():
        status, job = _api("GET", f"/api/jobs/{job_id}")
        assert status == 200, job
        samples.append((job.get("status"), job.get("progress") or 0))
        return job if job.get("status") in ("done", "error", "aborted") else None

    final = _wait_until(_poll, timeout=600, label=f"scan {job_id} to finish")
    assert final["status"] == "done", final
    stuck = [(s, p) for s, p in samples if s == "queued" and p > 0]
    assert not stuck, f"job read queued while progressing: {stuck[:5]}"
    assert any(
        s == "running" for s, _ in samples
    ), f"never flipped to running: {samples}"


def test_live_fingerprint_single_host(scoped_engagement):
    """Single-host fingerprint + vuln correlation for the target."""
    results = _fingerprint_target()
    hosts = [h for h in results.get("results", []) if h.get("ip") == TARGET]
    assert any(h.get("services") for h in hosts), results

    # vuln correlation must run cleanly; a patched host legitimately
    # yields zero matches, so only the shape is asserted here.
    status, vulns = _api("GET", "/api/neighbors/vulns")
    assert status == 200, vulns
    assert isinstance(vulns.get("vulns", None), list), vulns


def test_live_ui_scan_flow(driver, scoped_engagement):
    """Drive the real console: Discover scan, fingerprint, Recon shows it."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    from .helpers import go_to, wait_text

    driver.get(LIVE_URL)
    WebDriverWait(driver, 60).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "#target"))
    )
    go_to(driver, "discover")
    target_box = driver.find_element(By.ID, "target")
    target_box.clear()
    target_box.send_keys(TARGET)
    driver.find_element(By.ID, "btn-scan").click()
    try:
        wait_text(driver, "scan-status", "done", timeout=600)
    except Exception:
        status = driver.find_element(By.ID, "scan-status").text
        log = driver.find_element(By.CSS_SELECTOR, '[data-testid="activity-log"]').text
        driver.save_screenshot("/tmp/live-ui-failure.png")
        raise AssertionError(
            f"scan-status stuck at {status!r}; log tail: {log[-800:]}"
        ) from None
    wait_text(driver, "activity-log", "scan", timeout=60)
    # single-host fingerprint via API (the UI button sweeps all neighbors),
    # then the Recon tab must render the target from the neighbor store.
    _fingerprint_target()
    go_to(driver, "recon")
    wait_text(driver, "hosts-tbody", TARGET, timeout=120)


def _fingerprint_target():
    status, neighbors = _api("GET", "/api/neighbors")
    assert status == 200, neighbors
    if TARGET not in {h.get("ip") for h in neighbors.get("neighbors", [])}:
        status, _ = _api("POST", "/api/neighbors/scan", {})
        assert status == 200
        _wait_until(
            lambda: TARGET
            in {
                h.get("ip")
                for h in _api("GET", "/api/neighbors")[1].get("neighbors", [])
            },
            timeout=300,
            label=f"{TARGET} in neighbor discovery",
        )
    # A scanned host may briefly shun the scanner (filtered ports on the
    # first pass); one cooldown retry separates that from a real miss.
    last = None
    for _attempt in range(2):
        status, body = _api("POST", "/api/neighbors/fingerprint", {"ip": TARGET})
        assert status == 200, body
        fp_id = body["job_id"]

        def _poll(job_id):
            status, job = _api("GET", f"/api/neighbors/fingerprint/status/{job_id}")
            assert status == 200, job
            return job if job.get("status") in ("done", "error", "aborted") else None

        final = _wait_until(
            lambda fp_id=fp_id: _poll(fp_id),
            timeout=600,
            label="fingerprint to finish",
        )
        assert final["status"] == "done", final
        status, results = _api("GET", f"/api/neighbors/fingerprint/results/{fp_id}")
        assert status == 200, results
        hosts = [h for h in results.get("results", []) if h.get("ip") == TARGET]
        assert hosts, f"no result row for {TARGET}: {results}"
        if any(h.get("services") for h in hosts):
            return results
        last = results
        time.sleep(180)
    raise AssertionError(f"{TARGET} fingerprinted clean twice: {last}")
