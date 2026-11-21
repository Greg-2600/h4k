#!/usr/bin/env python3
"""Selenium walkthrough of the h4k dashboard and operator console.

Target: the contrived ``vulnlab`` container (intentionally buggy HTTP parser,
port 3138). The script drives the real UI, not the API:

dashboard : create scope -> scan -> fingerprint -> inspect services
ops       : acquire -> scan -> fingerprint -> fuzz -> session report

Run against a live stack::

    python scripts/e2e_ui_flow.py
    python scripts/e2e_ui_flow.py --base-url http://127.0.0.1:3137 \
        --target vulnlab --scope-cidr 172.18.0.0/24 --iterations 200

Screenshots land in ``artifacts/ui-flow/`` unless ``--screenshots`` is
overridden. Requires Chrome (Selenium Manager fetches the driver).
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait


class Flow:
    def __init__(self, driver: webdriver.Chrome, base: str, shots: Path) -> None:
        self.d = driver
        self.base = base.rstrip("/")
        self.shots = shots
        self.wait = WebDriverWait(driver, 30)
        self.steps: list[tuple[str, float]] = []

    # -- helpers ---------------------------------------------------------
    def go(self, path: str) -> None:
        self.d.get(f"{self.base}{path}")
        self.wait.until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

    def wait_text(self, selector: str, needle: str, timeout: float = 60) -> None:
        WebDriverWait(self.d, timeout).until(
            EC.text_to_be_present_in_element((By.CSS_SELECTOR, selector), needle)
        )

    def wait_visible(self, selector: str, timeout: float = 30) -> None:
        WebDriverWait(self.d, timeout).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, selector))
        )

    def shot(self, name: str) -> None:
        self.shots.mkdir(parents=True, exist_ok=True)
        path = self.shots / f"{name}.png"
        self.d.save_screenshot(str(path))
        print(f"    screenshot: {path}")

    def step(self, label: str) -> None:
        self.steps.append((label, time.monotonic()))
        print(f"  · {label}")

    def click(self, selector: str) -> None:
        element = self.wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
        )
        self.d.execute_script("arguments[0].scrollIntoView({block:'center'});", element)
        element.click()

    def fill(self, selector: str, value: str) -> None:
        element = self.wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, selector))
        )
        element.clear()
        element.send_keys(value)

    def body_text(self) -> str:
        return self.d.find_element(By.TAG_NAME, "body").text

    # -- dashboard flow --------------------------------------------------
    def dashboard(self, target: str, cidr: str) -> None:
        print("\n[dashboard] /")
        self.go("/")
        self.shot("01-dashboard-discover")

        self.step("create an authorized scope")
        self.fill("#scope-name", "Selenium UI pass")
        self.fill("#scope-cidrs", cidr)
        self.click("#btn-scope-create")
        self.wait_text("#scope-summary", cidr, timeout=20)
        self.shot("02-dashboard-scope")

        self.step(f"scan {target} (full depth)")
        self.fill("#target", target)
        Select(self.d.find_element(By.CSS_SELECTOR, "#depth-select")).select_by_value(
            "full"
        )
        self.click("#btn-scan")
        # The status pill goes running -> done; a full scan can take a while.
        self.wait_text("#scan-status", "done", timeout=240)
        self.shot("03-dashboard-scan-done")

    def dashboard_recon(self, target: str) -> None:
        """Fingerprint after discovery has populated the neighbor store."""
        print("\n[dashboard] / (Recon)")
        self.go("/")
        self.step("inspect the Recon tab (services are documented as console-only)")
        self.click('.ws-btn[data-tab="recon"]')
        self.shot("04-dashboard-recon")
        print("    note: dashboard Recon table stays empty; live services are in /ops")

    # -- ops flow --------------------------------------------------------
    def ops(
        self, target: str, iterations: int, timeout_s: int, download_dir: Path
    ) -> None:
        print("\n[ops] /ops")
        self.go("/ops")
        self.shot("05-ops-assets")

        self.step("expand Discover and scan the target")
        self.click("#btn-acquire")
        self.click("#tab-ip")
        self.fill("#target", target)
        Select(self.d.find_element(By.CSS_SELECTOR, "#depth-select")).select_by_value(
            "full"
        )
        self.click("#btn-launch-recon")
        WebDriverWait(self.d, 240).until(
            lambda d: any(
                word in d.find_element(By.CSS_SELECTOR, "#sp-status").text.lower()
                for word in ("complete", "done")
            )
        )
        self.shot("06-ops-scan-done")

        self.step("discover neighbors (required before fingerprinting)")
        self.click("#tab-neighbors")
        self.click("#btn-launch-recon")
        # The console auto-runs a common-port fingerprint after discovery, so
        # the progress strip is not a reliable completion signal. The activity
        # log is: "Found N neighbor(s)" then "Service map complete".
        WebDriverWait(self.d, 180).until(
            lambda d: "found"
            in d.find_element(By.CSS_SELECTOR, "#activity-log").text.lower()
        )
        WebDriverWait(self.d, 180).until(
            lambda d: "service map complete"
            in d.find_element(By.CSS_SELECTOR, "#activity-log").text.lower()
        )
        hosts = [
            h.text.splitlines()[0]
            for h in self.d.find_elements(By.CSS_SELECTOR, "#inventory-grid .tile")
        ]
        print(f"    neighbors: {hosts[:6]}")
        self.shot("06b-ops-neighbors")

        self.step("full-port fingerprint from the action panel")
        self.click("#btn-full-scan")
        WebDriverWait(self.d, 300).until(
            lambda d: "3138" in d.find_element(By.CSS_SELECTOR, "#fp-tbody").text
        )
        self.shot("07-ops-services")

        self.step(f"fuzz {target}:3138 ({iterations} iterations)")
        self.click('.nav-btn[data-phase="fuzz"]')
        self.fill("#fz-host", target)
        self.fill("#fz-port", "3138")
        self.fill("#fz-iters", str(iterations))
        self.fill("#fz-timeout", str(timeout_s))
        self.click("#btn-fz-start")
        # The start button is disabled while the job runs and re-enabled when
        # the poller sees a terminal state.
        WebDriverWait(self.d, 240).until(
            lambda d: d.find_element(By.CSS_SELECTOR, "#btn-fz-start").is_enabled()
        )
        WebDriverWait(self.d, 15).until(
            lambda d: "starting"
            not in d.find_element(By.CSS_SELECTOR, "#fz-live").text.lower()
        )
        print(
            f"    fuzz status: {self.d.find_element(By.CSS_SELECTOR, '#fz-live').text}"
        )
        print(
            f"    fuzz output: {self.d.find_element(By.CSS_SELECTOR, '#fz-output').text[:200]}"
        )
        self.shot("08-ops-fuzz")

        self.step("download the session report")
        download_dir.mkdir(parents=True, exist_ok=True)
        self.click('.nav-btn[data-phase="report"]')
        self.click("#btn-session-report")
        deadline = time.monotonic() + 30
        downloaded: Path | None = None
        while time.monotonic() < deadline and downloaded is None:
            files = [
                p
                for p in download_dir.glob("*")
                if p.is_file() and not p.name.endswith(".crdownload")
            ]
            if files:
                downloaded = max(files, key=lambda p: p.stat().st_mtime)
            else:
                time.sleep(0.5)
        assert downloaded is not None, "session report download did not start"
        print(f"    downloaded: {downloaded.name} ({downloaded.stat().st_size} bytes)")
        self.shot("09-ops-report")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:3137")
    parser.add_argument(
        "--target", default="vulnlab", help="contrived target host (container name)"
    )
    parser.add_argument("--scope-cidr", default="172.18.0.0/24")
    parser.add_argument("--iterations", type=int, default=150)
    parser.add_argument("--fuzz-timeout", type=int, default=45)
    parser.add_argument("--screenshots", default="artifacts/ui-flow")
    parser.add_argument("--downloads", default="/tmp/h4k-ui-flow-downloads")
    parser.add_argument("--headful", action="store_true")
    args = parser.parse_args()

    shots = Path(args.screenshots)
    download_dir = Path(args.downloads)

    options = Options()
    if not args.headful:
        options.add_argument("--headless=new")
    options.add_argument("--window-size=1440,1100")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-first-run")
    options.add_experimental_option(
        "prefs",
        {
            "download.default_directory": str(download_dir.resolve()),
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
        },
    )

    driver = webdriver.Chrome(options=options)
    started = time.monotonic()
    try:
        flow = Flow(driver, args.base_url, shots)
        flow.dashboard(args.target, args.scope_cidr)
        flow.ops(args.target, args.iterations, args.fuzz_timeout, download_dir)
        flow.dashboard_recon(args.target)
        elapsed = time.monotonic() - started
        print(f"\nOK — dashboard + ops flow completed in {elapsed:.1f}s")
        print(f"screenshots: {shots.resolve()}")
        return 0
    except (TimeoutException, AssertionError) as exc:
        driver.save_screenshot(str(Path(shots) / "failure.png"))
        print(f"\nFAIL — {type(exc).__name__}: {exc}", file=sys.stderr)
        print(
            f"failure screenshot: {(Path(shots) / 'failure.png').resolve()}",
            file=sys.stderr,
        )
        return 1
    finally:
        driver.quit()


if __name__ == "__main__":
    raise SystemExit(main())
