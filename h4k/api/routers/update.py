# Endpoints for periodic software-component auto-update within the container.
import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks
from services import updater

logger = logging.getLogger("h4k.routers.update")

router = APIRouter(prefix="/api")


@router.post("/update")
def trigger_update(background: BackgroundTasks) -> dict[str, Any]:
    """Trigger a one-off software update cycle (best-effort)."""
    # Run in the background so the request returns immediately; the cycle
    # refreshes semgrep/osv-scanner/trivy + CVE/creds data.
    background.add_task(updater.run_update)
    return {"status": "started"}


@router.get("/update/last")
def last_update() -> dict[str, Any]:
    """Return when the last update ran and its report (if any)."""
    state = updater.UPDATER_STATE
    if not state.exists():
        return {"last": None, "report": None}
    import json

    try:
        data = json.loads(state.read_text(encoding="utf-8"))
        return {"last": data.get("last"), "report": data.get("report")}
    except (OSError, json.JSONDecodeError):
        return {"last": None, "report": None, "error": "state unreadable"}


@router.get("/update/should")
def update_due() -> dict[str, Any]:
    """Check whether an update is due based on the configured interval."""
    return {"due": updater.should_run()}


@router.get("/cves/status")
def cve_status() -> dict[str, Any]:
    """CVE database state: when the data file was last written, age and size.

    `age_days` drives the Likely-Vulnerable header staleness flag (week+ old
    db gets an update button in the UI).
    """
    from datetime import UTC, datetime
    from pathlib import Path

    from services.cve_lookup import CveDb

    path = CveDb().path  # resolves to the same data file the matcher uses
    loaded_at: str | None
    age_days = -1
    if not path or not Path(path).exists():
        loaded_at = None
    else:
        mtime = Path(path).stat().st_mtime
        loaded_at = datetime.fromtimestamp(mtime, UTC).isoformat()
        age_days = (datetime.now(UTC) - datetime.fromtimestamp(mtime, UTC)).days

    cves = _cve_db_instance()
    count = len(cves.cves) if cves is not None else 0
    return {
        "loaded_at": loaded_at,
        "age_days": age_days,
        "count": count,
        "stale": age_days >= 7,
    }


@router.post("/cves/refresh")
def cve_refresh(background: BackgroundTasks) -> dict[str, Any]:
    """Refresh the offline CVE database (best-effort online fetch)."""
    db = _cve_db_instance()
    if db is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=503, detail="CVE db unavailable")

    def _run() -> None:
        ok = db.refresh()
        logger.info("CVE refresh completed: %s", ok)

    background.add_task(_run)
    return {"status": "started"}


def _cve_db_instance() -> Any | None:
    try:
        from app_state import cve_db as instance

        if instance is not None:
            return instance
    except Exception:
        pass
    try:
        from services.cve_lookup import CveDb

        return CveDb()
    except Exception:
        return None
