# Engagement endpoints: persistent per-engagement memory (hosts, services,
# credentials, vulns) and opt-in credential propagation.
#
# The scan router is deliberately stateless; this router is where a multi-hour
# engagement accumulates. Scope is enforced in the store, so these routes can
# only ever read or write hosts the engagement is authorized for.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from schemas import EngagementRequest, PropagateRequest
from services.engagement import EngagementStore, ScopeError, parse_scope
from services.propagate import MAX_ATTEMPTS, PropagationService

logger = logging.getLogger("h4k.routers.engagement")

router = APIRouter(prefix="/api/engagement")

_store: EngagementStore | None = None


def get_store() -> EngagementStore:
    global _store
    if _store is None:
        _store = EngagementStore()
    return _store


def _msf() -> Any:
    from app_state import msf_client

    return msf_client


@router.post("")
def create_engagement(req: EngagementRequest) -> dict[str, Any]:
    store = get_store()
    try:
        return store.create_engagement(req.name, req.scope, req.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("")
def list_engagements() -> dict[str, Any]:
    store = get_store()
    return {
        "engagements": [
            {**e, "summary": store.summary(e["id"])} for e in store.list_engagements()
        ]
    }


@router.post("/parse-scope")
def parse_scope_endpoint(body: dict[str, Any]) -> dict[str, Any]:
    """Turn a human-typed scope string into a validated CIDR list, so the UI
    can reject a bad scope before an engagement is created."""
    text = str((body or {}).get("text") or "")
    return {"scope": parse_scope(text)}


@router.get("/{engagement_id}")
def get_engagement(engagement_id: str) -> dict[str, Any]:
    store = get_store()
    eng = store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    return {**eng, "summary": store.summary(engagement_id)}


@router.delete("/{engagement_id}")
def delete_engagement(engagement_id: str) -> dict[str, Any]:
    if not get_store().delete_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return {"deleted": engagement_id}


@router.post("/{engagement_id}/ingest")
def ingest_scan(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Absorb a scan report. Accepts a raw report dict, or `{"job_id": ...}` to
    pull a finished scan job's report."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    report = body or {}
    if "job_id" in report and "hosts" not in report:
        from routers.scan import JOBS

        job = JOBS.get(str(report["job_id"]))
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        found = job.get("report")
        if found is None:
            raise HTTPException(status_code=404, detail="report not ready")
        # A finished job stores a pydantic Report, not a dict -- the old
        # isinstance(dict) check rejected every real job. Normalise first.
        if hasattr(found, "model_dump"):
            found = found.model_dump()
        report = found
    if not isinstance(report, dict) or "hosts" not in report:
        raise HTTPException(status_code=400, detail="report with 'hosts' required")
    try:
        return store.ingest_scan(engagement_id, report)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{engagement_id}/assets")
def list_assets(engagement_id: str) -> dict[str, Any]:
    return {"assets": get_store().assets(engagement_id)}


@router.get("/{engagement_id}/credentials")
def list_credentials(engagement_id: str) -> dict[str, Any]:
    """Credentials with every host each one was verified against — the
    lateral-movement picture."""
    return {
        "credentials": get_store().credentials(engagement_id),
        "access": get_store().access(engagement_id),
    }


@router.get("/{engagement_id}/graph")
def engagement_graph(engagement_id: str) -> dict[str, Any]:
    return get_store().graph(engagement_id)


@router.get("/{engagement_id}/propagate/plan")
def propagation_plan(engagement_id: str) -> dict[str, Any]:
    """Dry run: blast radius before authorizing anything. No network calls."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    msf = _msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="metasploit client unavailable")
    return PropagationService(msf, store).plan(engagement_id)


@router.post("/{engagement_id}/propagate")
def propagate(engagement_id: str, req: PropagateRequest) -> dict[str, Any]:
    """OPT-IN: replay verified engagement credentials across in-scope services."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    msf = _msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="metasploit client unavailable")
    svc = PropagationService(msf, store)
    cap = max(1, min(req.max_attempts, MAX_ATTEMPTS))
    return svc.run(engagement_id, open_sessions=req.open_sessions, max_attempts=cap)
