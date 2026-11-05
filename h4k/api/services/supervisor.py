# Supervision for h4k's in-container services: postgres, msfrpcd, tor,
# and the auto-scan thread.
#
# The entrypoint starts every daemon once at boot with no supervisor
# afterwards — a dead msfrpcd used to mean "msf down" until someone restarted
# the whole container. This module watches each service's liveness probe and
# restarts it with per-service backoff (at most N restarts per window, then
# it stays degraded until the window slides instead of hot-looping).
#
# Container-local only: every restart is a local subprocess or an in-process
# thread restart. Nothing here touches a target.
from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess  # nosec B404 - restarts local container daemons only
import threading
import time
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.supervisor")

DEFAULT_INTERVAL = 60
DEFAULT_MAX_RESTARTS = 3
DEFAULT_WINDOW_SECONDS = 600


def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def relaunch_msfrpcd(host: str, port: int, password: str) -> bool:
    exe = shutil.which("msfrpcd")
    if not exe:
        return False
    try:
        os.makedirs("/var/log/h4k", exist_ok=True)
        # fd intentionally inherited by the daemon process (stays open in child)
        logfile = open("/var/log/h4k/msfrpcd-watchdog.log", "ab")  # noqa: SIM115
        subprocess.Popen(  # nosec B603 - fixed argv, no shell
            [
                exe,
                "-a",
                host,
                "-p",
                str(port),
                "-U",
                "msf",
                "-P",
                password,
                "-S",
                "true",
                "-f",
            ],
            stdout=logfile,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return True
    except OSError as exc:
        logger.warning("msfrpcd relaunch failed: %s", exc)
        return False


def restart_service_unit(unit: str) -> bool:
    """Restart a container service via the service(8) wrapper (postgres, tor)."""
    if not shutil.which("service"):
        return False
    try:
        proc = (
            subprocess.run(  # nosec B603 B607 - fixed argv, service wrapper, no shell
                ["service", unit, "start"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("%s restart failed: %s", unit, exc)
        return False


class ServiceSpec:
    """One supervised thing: how to probe it, how to restart it."""

    def __init__(
        self,
        name: str,
        check: Callable[[], bool],
        restart: Callable[[], bool],
        max_restarts: int = DEFAULT_MAX_RESTARTS,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self.name = name
        self.check = check
        self.restart = restart
        self.max_restarts = max_restarts
        self.window_seconds = window_seconds
        self.ok: bool | None = None
        self.last_ok: float | None = None
        self.last_restart: float | None = None
        self.restarts_total = 0
        self._restart_times: list[float] = []
        self.degraded = False


class Supervisor:
    """Liveness loop with per-service restart budgets.

    `clock` is injectable so backoff is unit-testable without sleeping.
    """

    def __init__(
        self,
        specs: list[ServiceSpec] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.specs = specs if specs is not None else default_specs()
        self.clock = clock or time.time
        self._lock = threading.RLock()

    def _prune(self, spec: ServiceSpec, now: float) -> None:
        spec._restart_times = [
            t for t in spec._restart_times if now - t < spec.window_seconds
        ]

    def _budget_left(self, spec: ServiceSpec, now: float) -> bool:
        self._prune(spec, now)
        return len(spec._restart_times) < spec.max_restarts

    def tick(self) -> dict[str, Any]:
        """One pass: probe everything, restart what's down within budget."""
        now = self.clock()
        report: dict[str, Any] = {}
        with self._lock:
            for spec in self.specs:
                try:
                    alive = bool(spec.check())
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("%s probe failed: %s", spec.name, exc)
                    alive = False
                restarted = False
                if alive:
                    spec.ok = True
                    spec.last_ok = now
                    spec.degraded = False
                else:
                    spec.ok = False
                    if self._budget_left(spec, now):
                        restarted = bool(spec.restart())
                        if restarted:
                            spec._restart_times.append(now)
                            spec.last_restart = now
                            spec.restarts_total += 1
                            logger.warning(
                                "%s unreachable - restart attempted (%d in window)",
                                spec.name,
                                len(spec._restart_times),
                            )
                    else:
                        spec.degraded = True
                        logger.warning(
                            "%s unreachable - restart budget exhausted, degraded",
                            spec.name,
                        )
                report[spec.name] = {
                    "up": alive or restarted,
                    "degraded": spec.degraded,
                    "restarts_total": spec.restarts_total,
                    "last_ok": spec.last_ok,
                    "last_restart": spec.last_restart,
                }
        return report

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": bool(self.specs),
                "services": {
                    spec.name: {
                        "up": spec.ok,
                        "degraded": spec.degraded,
                        "restarts_total": spec.restarts_total,
                        "last_ok": spec.last_ok,
                        "last_restart": spec.last_restart,
                    }
                    for spec in self.specs
                },
            }


def _msf_host() -> str:
    return os.environ.get("MSF_HOST", "127.0.0.1")


def _msf_port() -> int:
    try:
        return int(os.environ.get("MSF_PORT", "55553"))
    except ValueError:
        return 55553


def _msf_password() -> str:
    return os.environ.get("MSF_PASSWORD", "h4k_msf_rocks")


def _db_port() -> int:
    try:
        return int(os.environ.get("MSF_DB_PORT", "5433"))
    except ValueError:
        return 5433


def _tor_port() -> int:
    try:
        return int(os.environ.get("TOR_PORT", "9050"))
    except ValueError:
        return 9050


def _auto_scan_alive() -> bool:
    try:
        import services.auto_scan as auto_scan_module

        st = auto_scan_module.status()
        return bool(st.get("running"))
    except Exception:
        return False


def _auto_scan_restart() -> bool:
    try:
        import services.auto_scan as auto_scan_module

        auto_scan_module.stop()
        auto_scan_module.start(force=True)
        return True
    except Exception as exc:
        logger.warning("auto-scan restart failed: %s", exc)
        return False


def default_specs() -> list[ServiceSpec]:
    """Specs for the real container. Empty under sandbox or missing binaries."""
    try:
        from services.sandbox import enabled as sandbox_enabled

        if sandbox_enabled():
            return []
    except Exception:
        pass
    specs: list[ServiceSpec] = []
    specs.append(
        ServiceSpec(
            "postgres",
            lambda: tcp_open("127.0.0.1", _db_port()),
            lambda: restart_service_unit("postgresql"),
        )
    )
    if shutil.which("msfrpcd"):
        specs.append(
            ServiceSpec(
                "msfrpcd",
                lambda: tcp_open(_msf_host(), _msf_port()),
                lambda: relaunch_msfrpcd(_msf_host(), _msf_port(), _msf_password()),
            )
        )
    specs.append(
        ServiceSpec(
            "tor",
            lambda: tcp_open("127.0.0.1", _tor_port()),
            lambda: restart_service_unit("tor"),
        )
    )
    specs.append(ServiceSpec("auto_scan", _auto_scan_alive, _auto_scan_restart))
    return specs


supervisor = Supervisor()
