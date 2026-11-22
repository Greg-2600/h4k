#!/usr/bin/env python3
"""Selenium walkthrough of the unified h4k dashboard.

Target: the contrived ``vulnlab`` container (intentionally buggy HTTP parser,
port 3138). The script drives one UI:

    Discover (scope + scan) -> Neighbors -> Recon (full-port fingerprint)
    -> Operations/Fuzz -> Operations/Report (download)

Run against a live stack::

    python scripts/e2e_ui_flow.py
    python scripts/e2e_ui_flow.py --headful --iterations 500

Screenshots land in ``artifacts/ui-flow/`` unless ``--screenshots`` is
overridden. Requires Chrome (Selenium Manager fetches the driver).
"""

from __future__ import annotations

import argparse
import subprocess
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

    def go(self, path: str) -> None:
        self.d.get(f"{self.base}{path}")
        self.wait.until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

    def shot(self, name: str) -> None:
        self.shots.mkdir(parents=True, exist_ok=True)
        path = self.shots / f"{name}.png"
        self.d.save_screenshot(str(path))
        print(f"    screenshot: {path}")

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

    def text(self, selector: str) -> str:
        return self.d.find_element(By.CSS_SELECTOR, selector).text

    def enter_ops(self, phase: str) -> None:
        """Open the Operations workspace and switch the embedded phase."""
        self.click('.ws-btn[data-tab="ops"]')
        self.click(f'#ops-phase-nav [data-ops-phase="{phase}"]')
        self.wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "#ops-frame")))
        frame = self.d.find_element(By.CSS_SELECTOR, "#ops-frame")
        self.d.switch_to.frame(frame)
        # The console switches phases through postMessage; wait for the phase.
        WebDriverWait(self.d, 30).until(
            EC.visibility_of_element_located((By.CSS_SELECTOR, f"#phase-{phase}"))
        )

    def leave_ops(self) -> None:
        self.d.switch_to.default_content()

    # -- dashboard: discover + recon -------------------------------------
    def discover(self, target: str, cidr: str) -> None:
        print("\n[dashboard] Discover")
        self.go("/")
        self.shot("01-discover")

        print("  · create an authorized scope")
        self.fill("#scope-name", "Selenium UI pass")
        self.fill("#scope-cidrs", cidr)
        self.click("#btn-scope-create")
        WebDriverWait(self.d, 20).until(
            lambda d: cidr in d.find_element(By.CSS_SELECTOR, "#scope-summary").text
        )

        print(f"  · scan {target} (full depth)")
        self.fill("#target", target)
        Select(self.d.find_element(By.CSS_SELECTOR, "#depth-select")).select_by_value(
            "full"
        )
        self.click("#btn-scan")
        WebDriverWait(self.d, 240).until(
            lambda d: "done"
            in d.find_element(By.CSS_SELECTOR, "#scan-status").text.lower()
        )
        self.shot("02-scan-done")

        print("  · discover neighbors (populates the service store)")
        self.click("#btn-neighbors")
        # The status still says "done" from the scan until the first poll;
        # wait for it to go back to running before waiting for completion.
        WebDriverWait(self.d, 15).until(
            lambda d: "running"
            in d.find_element(By.CSS_SELECTOR, "#scan-status").text.lower()
            or "done"
            not in d.find_element(By.CSS_SELECTOR, "#scan-status").text.lower()
        )
        WebDriverWait(self.d, 180).until(
            lambda d: "done"
            in d.find_element(By.CSS_SELECTOR, "#scan-status").text.lower()
        )
        self.shot("03-neighbors-done")

    def recon(self) -> None:
        print("\n[dashboard] Recon")
        self.click('.ws-btn[data-tab="recon"]')
        print("  · full-port fingerprint")
        self.click("#btn-full-scan")
        WebDriverWait(self.d, 300).until(
            lambda d: "3138" in d.find_element(By.CSS_SELECTOR, "#hosts-tbody").text
        )
        print("    services:", self.text("#hosts-count"))
        self.shot("04-recon-services")

    # -- operations: fuzz + report ---------------------------------------
    def fuzz(self, target: str, iterations: int, timeout_s: int) -> None:
        print("\n[operations] Fuzz")
        self.enter_ops("fuzz")
        self.shot("05-ops-fuzz")
        self.fill("#fz-host", target)
        self.fill("#fz-port", "3138")
        self.fill("#fz-iters", str(iterations))
        self.fill("#fz-timeout", str(timeout_s))
        self.click("#btn-fz-start")
        WebDriverWait(self.d, 240).until(
            lambda d: d.find_element(By.CSS_SELECTOR, "#btn-fz-start").is_enabled()
        )
        WebDriverWait(self.d, 15).until(
            lambda d: "starting"
            not in d.find_element(By.CSS_SELECTOR, "#fz-live").text.lower()
        )
        print("    status:", self.text("#fz-live"))
        print("    output:", self.text("#fz-output")[:160].replace("\n", " "))
        self.shot("06-ops-fuzz-done")
        self.leave_ops()

    def report(self, download_dir: Path) -> None:
        print("\n[operations] Report")
        self.enter_ops("report")
        self.shot("07-ops-report")
        download_dir.mkdir(parents=True, exist_ok=True)
        self.click("#btn-session-report")
        self.leave_ops()
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


def restart_target() -> None:
    """Restart the contrived target so the fuzz baseline is up."""
    compose = Path(__file__).resolve().parent.parent / "h4k" / "docker-compose.yml"
    subprocess.run(
        ["docker", "compose", "-f", str(compose), "restart", "vulnlab"],
        check=False,
        capture_output=True,
    )
    for _ in range(45):
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Health.Status}}", "h4k_vulnlab"],
            capture_output=True,
            text=True,
            check=False,
        )
        if "healthy" in out.stdout:
            return
        time.sleep(1)
    print("    warning: vulnlab did not report healthy in 45s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:3137")
    parser.add_argument("--target", default="vulnlab")
    parser.add_argument("--scope-cidr", default="172.18.0.0/24")
    parser.add_argument("--iterations", type=int, default=80)
    parser.add_argument("--fuzz-timeout", type=int, default=10)
    parser.add_argument(
        "--no-restart-target",
        action="store_true",
        help="do not restart vulnlab before fuzzing (the fuzz step may crash it)",
    )
    parser.add_argument("--screenshots", default="artifacts/ui-flow")
    parser.add_argument("--downloads", default="/tmp/h4k-ui-flow-downloads")
    parser.add_argument("--headful", action="store_true")
    args = parser.parse_args()

    options = Options()
    if not args.headful:
        options.add_argument("--headless=new")
    options.add_argument("--window-size=1440,1100")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-first-run")
    options.add_experimental_option(
        "prefs",
        {
            "download.default_directory": str(Path(args.downloads).resolve()),
            "download.prompt_for_download": False,
            "download.directory_upgrade": True,
        },
    )

    driver = webdriver.Chrome(options=options)
    started = time.monotonic()
    try:
        flow = Flow(driver, args.base_url, Path(args.screenshots))
        flow.discover(args.target, args.scope_cidr)
        flow.recon()
        if not args.no_restart_target:
            print("\n[target] restarting vulnlab so the fuzz baseline is reachable")
            restart_target()
        flow.fuzz(args.target, args.iterations, args.fuzz_timeout)
        flow.report(Path(args.downloads))
        print(f"\nOK — unified UI flow completed in {time.monotonic() - started:.1f}s")
        print(f"screenshots: {Path(args.screenshots).resolve()}")
        return 0
    except (TimeoutException, AssertionError) as exc:
        driver.save_screenshot(str(Path(args.screenshots) / "failure.png"))
        print(f"\nFAIL — {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        driver.quit()


if __name__ == "__main__":
    raise SystemExit(main())
