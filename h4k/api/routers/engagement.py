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


@router.post("/{engagement_id}/crown-jewels")
def add_crown_jewel(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Declare a crown jewel / objective for this engagement."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    host = str((body or {}).get("host") or "").strip()
    label = (body or {}).get("label")
    value = (body or {}).get("value", 50)
    try:
        return store.add_crown_jewel(engagement_id, host, label, value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sandbox-seed")
def sandbox_seed() -> dict[str, Any]:
    """Seed a demo engagement (sandbox mode only).

    Creates an engagement over the fixed lab estate, ingests a canned scan
    report, records two verified credentials that pivot across hosts, and
    declares the domain controller as a crown jewel. Used by the class demo
    and by the Selenium suite so both see identical data.
    """
    from services.sandbox import enabled as sandbox_enabled, seed_engagement

    if not sandbox_enabled():
        raise HTTPException(
            status_code=404, detail="sandbox mode is off (set H4K_SANDBOX=1)"
        )
    store = get_store()
    eng = seed_engagement(store)
    return {"engagement": eng, "summary": store.summary(eng["id"])}


@router.get("/{engagement_id}/crown-jewels")
def list_crown_jewels(engagement_id: str) -> dict[str, Any]:
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return {"crown_jewels": store.list_crown_jewels(engagement_id)}


@router.delete("/{engagement_id}/crown-jewels/{crown_id}")
def delete_crown_jewel(engagement_id: str, crown_id: str) -> dict[str, Any]:
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    if not store.delete_crown_jewel(engagement_id, crown_id):
        raise HTTPException(status_code=404, detail="crown jewel not found")
    return {"deleted": crown_id}


@router.get("/{engagement_id}/attack-paths")
def attack_paths(
    engagement_id: str,
    crown_jewel_id: str | None = None,
    max_depth: int = 6,
    limit: int = 25,
    fmt: str = "json",
) -> dict[str, Any]:
    """Compute evidence-backed paths from plausible footholds to crown jewels.

    `fmt=md` returns a markdown writeup instead of JSON (for the report and
    for pasting into a delivery note).
    """
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.attack_paths import compute_attack_paths, paths_to_markdown

    result = compute_attack_paths(
        store,
        engagement_id,
        crown_jewel_id=crown_jewel_id,
        max_depth=max_depth,
        limit=limit,
    )
    if fmt.lower() in ("md", "markdown"):
        return {
            "fmt": "md",
            "content": paths_to_markdown(result),
            "summary": result.get("summary", {}),
        }
    return result


@router.get("/{engagement_id}/export")
def export_engagement(engagement_id: str) -> dict[str, Any]:
    """Export the whole engagement as a portable snapshot.

    The snapshot can be handed to a colleague (or archived) and imported into
    another engagement with `POST /{id}/import`.
    """
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.engagement import export_snapshot

    return export_snapshot(store, engagement_id)


@router.post("/{engagement_id}/import")
def import_engagement(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Merge a snapshot into an engagement.

    Every host in the snapshot is scope-checked: anything outside the
    engagement's authorized CIDRs is skipped and reported, never recorded.
    """
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.engagement import import_snapshot

    try:
        return import_snapshot(store, engagement_id, body or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{engagement_id}/flags")
def list_flags(engagement_id: str) -> dict[str, Any]:
    """All captured flags for this engagement."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.flags import FlagStore

    fs = FlagStore()
    return {"flags": fs.list_flags(engagement_id), "count": fs.count(engagement_id)}


@router.post("/{engagement_id}/flags")
def record_flag(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Record a captured flag."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.flags import FlagStore

    value = str((body or {}).get("value") or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="value required")
    fs = FlagStore()
    try:
        flag = fs.record(
            engagement_id,
            value,
            host=(body or {}).get("host"),
            path=(body or {}).get("path"),
            method=(body or {}).get("method"),
            note=str((body or {}).get("note") or ""),
            auto=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"flag": flag, "total": fs.count(engagement_id)}


@router.post("/{engagement_id}/flags/detect")
def detect_flags(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Scan text (session recon output, file dumps, ...) for flag-shaped strings
    and record any new ones as auto-detected flags."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    text = str((body or {}).get("text") or "")
    if not text:
        raise HTTPException(status_code=400, detail="text required")
    from services.flags import FlagStore

    fs = FlagStore()
    new_flags = []
    for value in FlagStore.detect(text):
        flag = fs.record(engagement_id, value, auto=True)
        new_flags.append(flag)
    return {
        "detected": new_flags,
        "count": len(new_flags),
        "total": fs.count(engagement_id),
    }


@router.delete("/{engagement_id}/flags/{flag_id}")
def delete_flag(engagement_id: str, flag_id: str) -> dict[str, Any]:
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.flags import FlagStore

    fs = FlagStore()
    if not fs.delete(flag_id):
        raise HTTPException(status_code=404, detail="flag not found")
    return {"deleted": flag_id, "total": fs.count(engagement_id)}


@router.get("/{engagement_id}/next-move")
def next_move_endpoint(engagement_id: str) -> dict[str, Any]:
    """The ranked 'next move' queue for this engagement."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.next_move import build_next_move

    return build_next_move(store, engagement_id)


@router.get("/{engagement_id}/attck")
def engagement_attck(engagement_id: str) -> dict[str, Any]:
    """Map an engagement's findings to ATT&CK techniques + detection guidance."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.attck import enrich_engagement

    return enrich_engagement(store, engagement_id)


@router.get("/attck/techniques")
def attck_techniques() -> dict[str, Any]:
    from services.attck import TECHNIQUES

    return {"techniques": list(TECHNIQUES.values())}


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
