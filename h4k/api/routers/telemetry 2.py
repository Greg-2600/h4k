# Endpoint telemetry endpoints (#94): ingest, query, detections, summary.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services.telemetry import MAX_BATCH, TelemetryStore, rules, simulate_demo

logger = logging.getLogger("h4k.routers.telemetry")

router = APIRouter(prefix="/api/telemetry")

_store: TelemetryStore | None = None


def get_store() -> TelemetryStore:
    global _store
    if _store is None:
        _store = TelemetryStore()
    return _store


def reset_store() -> None:
    global _store
    _store = None


@router.get("/rules")
def telemetry_rules() -> dict[str, Any]:
    return {"rules": rules(), "max_batch": MAX_BATCH}


@router.post("/events")
def ingest_events(body: dict[str, Any]) -> dict[str, Any]:
    events = (body or {}).get("events")
    if events is None and (body or {}).get("message"):
        events = [body]
    if not isinstance(events, list) or not events:
        raise HTTPException(
            status_code=400, detail="events must be a non-empty list (or one event)"
        )
    events = [e for e in events if isinstance(e, dict)]
    if not events:
        raise HTTPException(status_code=400, detail="no event objects in batch")
    if len(events) > MAX_BATCH:
        raise HTTPException(
            status_code=400,
            detail=f"batch too large: {len(events)} > {MAX_BATCH}",
        )
    source = str((body or {}).get("source") or "manual")
    try:
        result = get_store().ingest(events, source=source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info(
        "telemetry ingest: %s accepted, %s duplicates, %s detections",
        result["accepted"],
        result["duplicates"],
        result["detection_count"],
    )
    return result


@router.get("/events")
def list_events(
    limit: int = 200,
    host: str = "",
    source: str = "",
    technique: str = "",
    severity: str = "",
    q: str = "",
    since: str = "",
) -> dict[str, Any]:
    events = get_store().events(
        limit=limit,
        host=host,
        source=source,
        technique=technique,
        severity=severity,
        q=q,
        since=since,
    )
    return {"events": events, "count": len(events)}


@router.get("/detections")
def list_detections(limit: int = 200) -> dict[str, Any]:
    detections = get_store().detections(limit=limit)
    return {"detections": detections, "count": len(detections)}


@router.get("/summary")
def telemetry_summary() -> dict[str, Any]:
    return get_store().summary()


@router.post("/simulate")
def simulate() -> dict[str, Any]:
    """Ingest a small canned attack chain so the detection view is demoable."""
    demo = simulate_demo()
    result = get_store().ingest(demo["events"], source=demo["source"])
    return {**result, "note": "canned demo telemetry; no live action was performed"}


@router.post("/reset")
def reset_telemetry() -> dict[str, Any]:
    return get_store().reset()
