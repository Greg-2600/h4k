# Nightly autopilot endpoints (#100): cron schedules, validation, run history.
#
# Scheduling is opt-in (H4K_SCHEDULER=1 starts the background loop). These routes
# exist even when the loop is off so an operator can stage schedules, inspect the
# next five run times, and trigger one manually.
import logging
import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from services import nightly

logger = logging.getLogger("h4k.routers.automation")

router = APIRouter(prefix="/api/automation")

_scheduler: nightly.NightlyScheduler | None = None
_lock = threading.Lock()


def get_scheduler() -> nightly.NightlyScheduler:
    global _scheduler
    with _lock:
        if _scheduler is None:
            _scheduler = nightly.NightlyScheduler()
        return _scheduler


def reset_scheduler() -> None:
    global _scheduler
    with _lock:
        _scheduler = None


def _engagement_exists(engagement_id: str) -> bool:
    if not engagement_id:
        return False
    try:
        from services.engagement import EngagementStore

        return any(
            e["id"] == engagement_id for e in EngagementStore().list_engagements()
        )
    except Exception:  # pragma: no cover - store unavailable in a partial test
        return True


@router.get("/status")
def automation_status() -> dict[str, Any]:
    scheduler = get_scheduler()
    schedules = scheduler.store.list_all()
    return {
        "enabled": nightly.scheduler_enabled(),
        "running": scheduler.running,
        "schedules": len(schedules),
        "enabled_schedules": sum(1 for s in schedules if s["enabled"]),
        "due": len(scheduler.store.due()),
        "store": str(scheduler.store.path),
        "timezone_note": "schedules store UTC next_run; each schedule has its own tz",
    }


@router.post("/validate")
def validate_cron(body: dict[str, Any]) -> dict[str, Any]:
    expression = str((body or {}).get("cron") or "")
    tz = str((body or {}).get("timezone") or "UTC")
    try:
        schedule = nightly.parse_cron(expression)
        upcoming = nightly.upcoming(
            expression,
            count=int((body or {}).get("count") or 5),
            tz=tz,
        )
    except nightly.CronError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "valid": True,
        "cron": expression,
        "normalized": schedule.expression,
        "next_runs": upcoming,
    }


@router.get("/schedules")
def list_schedules() -> dict[str, Any]:
    return {"schedules": get_scheduler().store.list_all()}


@router.post("/schedules")
def create_schedule(body: dict[str, Any]) -> dict[str, Any]:
    body = body or {}
    engagement_id = str(body.get("engagement_id") or "")
    if not engagement_id:
        raise HTTPException(
            status_code=400,
            detail="engagement_id is required: an unattended run still needs an authorized scope",
        )
    if not _engagement_exists(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    try:
        schedule = get_scheduler().store.create(
            str(body.get("name") or ""),
            str(body.get("cron") or ""),
            engagement_id=engagement_id,
            deep_web=bool(body.get("deep_web")),
            enabled=bool(body.get("enabled", True)),
            timezone=str(body.get("timezone") or "UTC"),
        )
    except (ValueError, nightly.CronError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("nightly schedule created: %s (%s)", schedule["name"], schedule["cron"])
    return schedule


@router.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: str) -> dict[str, Any]:
    schedule = get_scheduler().store.get(schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return schedule


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        return get_scheduler().store.update(schedule_id, body or {})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="schedule not found") from exc
    except (ValueError, nightly.CronError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str) -> dict[str, Any]:
    if not get_scheduler().store.delete(schedule_id):
        raise HTTPException(status_code=404, detail="schedule not found")
    return {"status": "deleted", "id": schedule_id}


@router.post("/schedules/{schedule_id}/run")
def run_schedule(
    schedule_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    scheduler = get_scheduler()
    schedule = scheduler.store.get(schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    if (body or {}).get("wait"):
        result = scheduler.run_now(schedule_id)
        return {"status": result.get("status", "complete"), "result": result}
    threading.Thread(target=scheduler.run_now, args=(schedule_id,), daemon=True).start()
    return {"status": "started", "schedule_id": schedule_id}


@router.get("/runs")
def list_runs(schedule_id: str = "", limit: int = 50) -> dict[str, Any]:
    return {
        "runs": get_scheduler().store.runs(schedule_id, limit=limit),
    }


@router.get("/schedules/{schedule_id}/runs")
def schedule_runs(schedule_id: str, limit: int = 50) -> dict[str, Any]:
    if get_scheduler().store.get(schedule_id) is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return {"runs": get_scheduler().store.runs(schedule_id, limit=limit)}
