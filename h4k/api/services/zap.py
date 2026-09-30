# OWASP ZAP integration: headless web application scanner with active/passive
# scanning, spider, AJAX spider, fuzzer and REST API. For authorized targets.
import json
import logging
import subprocess  # nosec B404 - launches the ZAP daemon
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("h4k.zap")

ZAP_HOME = Path("/opt/zap")
ZAP_DAEMON_PORT = 8090
ZAP_API_KEY = "h4k_zap_key"


class ZAPService:
    """OWASP ZAP headless scanner driven over its REST API."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)
        self.base_url = f"http://127.0.0.1:{ZAP_DAEMON_PORT}"
        self.api_key = ZAP_API_KEY
        self._process: subprocess.Popen[str] | None = None

    def start(self, timeout: int = 60) -> bool:
        """Start the ZAP daemon in headless mode."""
        if self.is_running():
            return True
        self.progress("starting OWASP ZAP daemon", 10)
        cmd = [
            "zap",
            "-daemon",
            "-port",
            str(ZAP_DAEMON_PORT),
            "-host",
            "127.0.0.1",
            "-config",
            f"api.key={self.api_key}",
            "-config",
            "api.addrs.addr.name=.*",
            "-config",
            "api.addrs.addr.regex=True",
        ]
        try:
            self._process = subprocess.Popen(  # nosec B603 - fixed argv, no shell
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
        except FileNotFoundError:
            logger.error("ZAP launcher not found (expected /opt/zap/zap.sh)")
            return False

        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.is_running():
                self.progress("ZAP daemon ready", 100)
                return True
            time.sleep(2)
        logger.error("ZAP daemon failed to start within %ds", timeout)
        return False

    def is_running(self) -> bool:
        try:
            resp = requests.get(
                f"{self.base_url}/JSON/core/view/version/",
                params={"apikey": self.api_key},
                timeout=3,
            )
            return resp.status_code == 200
        except Exception:  # connection refused, DNS, timeout, ...
            return False

    def stop(self) -> None:
        if not self._process:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
        self._process = None

    def _call(
        self, endpoint: str, params: dict[str, Any] | None = None, method: str = "GET"
    ) -> dict[str, Any]:
        url = f"{self.base_url}/JSON/{endpoint}/"
        query = dict(params or {})
        query["apikey"] = self.api_key
        try:
            if method == "GET":
                resp = requests.get(url, params=query, timeout=30)
            else:
                resp = requests.post(url, data=query, timeout=30)
            data = resp.json()
            return data if isinstance(data, dict) else {"result": data}
        except Exception as exc:  # requests down, bad JSON, etc.
            logger.error("ZAP API call failed: %s", exc)
            return {}

    # ---- Spider / JS spider -------------------------------------------------
    def spider_scan(
        self, target: str, max_children: int = 10, recurse: bool = True
    ) -> dict[str, Any]:
        self.progress(f"spidering {target}", 0)
        self._call(
            "spider/action/scan/",
            {
                "url": target,
                "maxChildren": str(max_children),
                "recurse": str(recurse).lower(),
            },
        )
        return self._wait_for_spider()

    def ajax_spider_scan(
        self, target: str, browser_id: str = "firefox"
    ) -> dict[str, Any]:
        self.progress(f"AJAX spidering {target}", 0)
        self._call("ajaxSpider/action/scan/", {"url": target, "browserId": browser_id})
        return self._wait_for_ajax_spider()

    def _wait_for_spider(self, timeout: int = 300) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._call("spider/view/status/")
            pct = int(status.get("status", "0") or 0)
            self.progress(f"spider progress: {pct}%", pct)
            if pct >= 100:
                break
            time.sleep(3)
        return {"status": "completed", "progress": 100}

    def _wait_for_ajax_spider(self, timeout: int = 300) -> dict[str, Any]:
        deadline = time.time() + timeout
        state = "running"
        while time.time() < deadline:
            status = self._call("ajaxSpider/view/status/")
            state = status.get("status", "running")
            self.progress(f"AJAX spider: {state}", 0)
            if state != "running":
                break
            time.sleep(5)
        return {"status": state}

    # ---- Active scan --------------------------------------------------------
    def active_scan(
        self, target: str, policy: str | None = None, max_scan_duration: int = 0
    ) -> dict[str, Any]:
        self.progress(f"active scanning {target}", 0)
        params: dict[str, Any] = {"url": target}
        if policy:
            params["scanPolicyName"] = policy
        if max_scan_duration:
            params["maxScanDurationInMins"] = str(max_scan_duration)
        self._call("ascan/action/scan/", params)
        return self._wait_for_active_scan()

    def _wait_for_active_scan(self, timeout: int = 600) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._call("ascan/view/status/")
            pct = int(status.get("status", "0") or 0)
            self.progress(f"active scan: {pct}%", pct)
            if pct >= 100:
                break
            time.sleep(5)
        return {"status": "completed", "progress": 100}

    # ---- Alerts / results ---------------------------------------------------
    def get_alerts(
        self, target: str | None = None, risk_level: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if target:
            params["baseurl"] = target
        if risk_level:
            params["riskId"] = risk_level
        result = self._call("core/view/alerts/", params)
        alerts = result.get("alerts", [])
        return alerts if isinstance(alerts, list) else []

    def get_alert_count(self, target: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if target:
            params["baseurl"] = target
        return self._call("core/view/numberOfAlerts/", params)

    # ---- Context / auth -----------------------------------------------------
    def create_context(self, name: str, target: str) -> str | None:
        result = self._call("context/action/newContext/", {"contextName": name})
        ctx_id = result.get("contextId")
        if ctx_id:
            self._call(
                "context/action/includeInContext/",
                {"contextId": ctx_id, "regex": target + ".*"},
            )
        return str(ctx_id) if ctx_id is not None else None

    def set_auth(
        self, context_id: str, auth_method: str, params: dict[str, Any]
    ) -> None:
        self._call(
            "authentication/action/setAuthenticationMethod/",
            {
                "contextId": context_id,
                "authMethodName": auth_method,
                "authMethodConfigParams": json.dumps(params),
            },
        )

    # ---- Fuzzer / reports ---------------------------------------------------
    def fuzz(self, target: str, fuzzers: list[str] | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"url": target}
        if fuzzers:
            params["fuzzers"] = ",".join(fuzzers)
        self._call("fuzzer/action/fuzz/", params)
        return {"status": "started"}

    def generate_report(
        self, template: str = "traditional-html", target: str | None = None
    ) -> str | None:
        params: dict[str, Any] = {"template": template}
        if target:
            params["baseurl"] = target
        result = self._call("reports/action/generate/", params)
        report = result.get("report")
        return str(report) if report is not None else None


class ZAPRunner:
    """High-level ZAP scan orchestration for CTF/web targets."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.zap = ZAPService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def full_scan(
        self,
        target: str,
        authenticated: bool = False,
        credentials: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Full scan: spider + active scan + alerts + report."""
        if not self.zap.start():
            return {"error": "ZAP failed to start"}
        try:
            self.progress("ZAP full scan started", 5)
            self.zap.spider_scan(target)
            self.progress("spider done", 30)
            self.zap.active_scan(target)
            self.progress("active scan done", 80)
            alerts = self.zap.get_alerts(target)
            self.progress("collected alerts", 90)
            report = self.zap.generate_report("traditional-html", target)
            return {
                "target": target,
                "alerts": alerts,
                "alert_count": len(alerts),
                "high_risk": [a for a in alerts if a.get("risk") == "High"],
                "medium_risk": [a for a in alerts if a.get("risk") == "Medium"],
                "report_html": report or "",
            }
        finally:
            self.zap.stop()


def zap_scan(target: str, mode: str = "full", **kwargs: Any) -> dict[str, Any]:
    """Convenience function for API integration."""
    runner = ZAPRunner()
    if mode in ("spider", "active"):
        if not runner.zap.start():
            return {"error": "ZAP failed to start"}
        try:
            if mode == "spider":
                return runner.zap.spider_scan(target)
            return runner.zap.active_scan(target)
        finally:
            runner.zap.stop()
    return runner.full_scan(target, **kwargs)
