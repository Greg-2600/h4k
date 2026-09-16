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
