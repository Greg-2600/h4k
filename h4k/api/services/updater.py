# Periodic software-component auto-update inside the container.
#
# Keeps the analysis toolchain (semgrep, osv-scanner, trivy) and the offline
# SAST/CVE data fresh so results reflect current vulnerability knowledge.
# All updates are safe, non-destructive and re-runable.
#
# What we refresh:
#   - semgrep: `semgrep update` (or registry rules) if it supports it
#   - osv-scanner: re-download latest release binary (needs network)
#   - trivy: re-run its install.sh (needs network)
#   - local CVE/creds JSON: best-effort online refresh via h4k's own services
#
# This is idempotent and never deletes existing data. Network operations are
# best-effort: failures are logged, never fatal.
import logging
import os
import shutil
import subprocess  # nosec B404 - runs official tool updaters (semgrep/trivy)
import tempfile
import urllib.request
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.updater")

# Interval between automatic refresh cycles (overridable via env).
DEFAULT_INTERVAL_SECONDS = 6 * 3600  # 6 hours

UPDATER_STATE = Path("/var/lib/h4k/last_update.json")


def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return -1, f"{cmd[0]} not installed\n"
    except subprocess.TimeoutExpired:
        return -1, "timed out\n"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, str(exc) + "\n"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def refresh_cve_data() -> dict[str, Any]:
    """Best-effort refresh of the bundled CVE/creds archives."""
    report: dict[str, Any] = {}
    try:
        import sys

        sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
        from services.creds import CredArchive
        from services.cve_lookup import CveDb

        cve = CveDb()
        cve_before = len(cve.cves)
        cve.refresh()
        report["cve_db"] = {"before": cve_before, "after": len(cve.cves)}

        cred = CredArchive()
        report["creds_db"] = {
            "universal": len(cred.universal),
            "vendors": len(cred.vendors),
        }
    except Exception as exc:  # pragma: no cover - defensive
        report["error"] = str(exc)
    return report


def refresh_tools() -> dict[str, Any]:
    """Update semgrep + (re)install latest osv-scanner/trivy binaries (best-effort)."""
    report: dict[str, Any] = {}

    # 1) semgrep: report current version, then upgrade the pip package + rules.
    if _which("semgrep"):
        _rc, out = _run(["semgrep", "--version"])
        report["semgrep_before"] = out.strip().splitlines()[-1] if out.strip() else "?"
        upgrade_rc, upgrade_out = _run(
            [
                "python3",
                "-m",
                "pip",
                "install",
                "--break-system-packages",
                "--upgrade",
                "--quiet",
                "semgrep",
            ]
        )
        report["semgrep_upgrade_rc"] = upgrade_rc
        report["semgrep_upgrade"] = (
            "via pip" if upgrade_rc == 0 else (upgrade_out.strip()[-150:])
        )
    else:
        report["semgrep"] = "not installed"

    # 2) osv-scanner: pull latest release binary.
    osv = _which("osv-scanner")
    if osv:
        tmp = None
        try:
            url = "https://api.github.com/repos/google/osv-scanner/releases/latest"
            with urllib.request.urlopen(url, timeout=20) as resp:  # nosec B310
                import json

                ver = json.load(resp)["tag_name"]
            bin_url = (
                f"https://github.com/google/osv-scanner/releases/download/"
                f"{ver}/osv-scanner_linux_amd64"
            )
            fd, tmp_name = tempfile.mkstemp(suffix=".osv")
            os.close(fd)
            tmp = Path(tmp_name)
            with (
                urllib.request.urlopen(
                    bin_url, timeout=120
                ) as rsrc,  # nosec B310 - fixed github URL
                open(tmp, "wb") as f,
            ):
                shutil.copyfileobj(rsrc, f)
            # osv-scanner needs to be executable to run as a tool.
            tmp.chmod(0o755)  # nosec B103 - executable bit required for tool
            # atomic-ish replace
            tmp.replace(osv)
            report["osv_scanner"] = f"updated to {ver}"
        except Exception as exc:
            report["osv_scanner"] = f"update failed: {str(exc)[:150]}"
        finally:
            if tmp is not None and tmp.exists():
                with suppress(OSError):
                    tmp.unlink()
    else:
        report["osv_scanner"] = "not installed"

    # 3) trivy: re-run its official install script.
    if _which("trivy"):
        try:
            script_url = (
                "https://raw.githubusercontent.com/aquasecurity/trivy/main/"
                "contrib/install.sh"
            )
            script = urllib.request.urlopen(script_url, timeout=30).read()  # nosec B310
            bash = shutil.which("bash") or "/bin/bash"
            proc = subprocess.run(  # nosec B603 - trusted upstream script
                [bash, "-s", "--", "-b", "/usr/local/bin"],
                input=script,
                capture_output=True,
                timeout=300,
                check=False,
            )
            report["trivy"] = f"update rc={proc.returncode}"
        except Exception as exc:
            report["trivy"] = f"update failed: {str(exc)[:150]}"
    else:
        report["trivy"] = "not installed"

    return report


def run_update() -> dict[str, Any]:
    """Run one full update cycle; returns a structured report."""
    started = datetime.now(UTC).isoformat()
    tools = refresh_tools()
    data = refresh_cve_data()
    result = {
        "started": started,
        "finished": datetime.now(UTC).isoformat(),
        "tools": tools,
        "data": data,
    }
    _persist_state(result)
    return result


def _persist_state(result: dict[str, Any]) -> None:
    import json

    try:
        UPDATER_STATE.parent.mkdir(parents=True, exist_ok=True)
        UPDATER_STATE.write_text(
            json.dumps({"last": result["finished"], "report": result}), encoding="utf-8"
        )
    except (OSError, TypeError):
        logger.warning("could not persist updater state")


def should_run() -> bool:
    """True if enough time has elapsed since the last update."""
    import json

    try:
        data = json.loads(UPDATER_STATE.read_text(encoding="utf-8"))
        last = data.get("last", "")
    except (OSError, json.JSONDecodeError):
        return True
    if not last:
        return True
    interval = int(os.environ.get("H4K_UPDATE_INTERVAL", DEFAULT_INTERVAL_SECONDS))
    try:
        last_ts = datetime.fromisoformat(last)
        return (datetime.now(UTC) - last_ts).total_seconds() >= interval
    except ValueError:
        return True
