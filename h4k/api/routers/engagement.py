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


@router.post("/{engagement_id}/watch/baseline")
def watch_baseline(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Snapshot the in-scope estate now and diff it against the previous one.

    Accepts a raw report dict, or `{"job_id": ...}` to snapshot a finished
    scan job's report. Out-of-scope hosts are dropped before snapshotting.
    """
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
        if hasattr(found, "model_dump"):
            found = found.model_dump()
        report = found
    if not isinstance(report, dict) or "hosts" not in report:
        raise HTTPException(status_code=400, detail="report with 'hosts' required")
    return store.record_watch_snapshot(engagement_id, report, source="manual")


@router.get("/{engagement_id}/watch/changes")
def watch_changes(engagement_id: str, limit: int = 20) -> dict[str, Any]:
    if not get_store().get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return {"changes": get_store().watch_changes(engagement_id, limit=limit)}


@router.get("/{engagement_id}/watch/status")
def watch_status(engagement_id: str) -> dict[str, Any]:
    if not get_store().get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return get_store().watch_status(engagement_id)


@router.get("/{engagement_id}/watch/config")
def watch_config(engagement_id: str) -> dict[str, Any]:
    store = get_store()
    try:
        return store.get_watch_config(engagement_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="engagement not found") from None


@router.post("/{engagement_id}/watch/config")
def watch_config_set(engagement_id: str, body: dict[str, Any]) -> dict[str, Any]:
    store = get_store()
    try:
        return store.set_watch_config(
            engagement_id,
            mode=(body or {}).get("mode"),
            retain=(body or {}).get("retain"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{engagement_id}/watch/trends")
def watch_trends(engagement_id: str, limit: int = 100) -> dict[str, Any]:
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return store.watch_trends(engagement_id, limit=limit)


@router.post("/{engagement_id}/watch/verify")
def watch_verify(
    engagement_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify-fix: snapshot the freshest finished scan data and diff it.

    Run a scan first (scan button, autopilot, or auto-scan), then verify:
    the newest finished scan job covering `host` (or any finished job) is
    snapshotted with source "verify" and diffed against the previous pass.
    A cleared finding after your patch shows up as cleared_vulns.
    """
    from routers.scan import JOBS

    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    host = ((body or {}).get("host") or "").strip() or None
    best_key: str | None = None
    best_found: dict[str, Any] | None = None
    best_created = ""
    for key, job in JOBS.items():
        if not isinstance(job, dict) or job.get("status") not in ("done", "completed"):
            continue
        found = job.get("report")
        if found is None:
            continue
        if hasattr(found, "model_dump"):
            found = found.model_dump()
        if not isinstance(found, dict) or "hosts" not in found:
            continue
        if host and not any(h.get("address") == host for h in found.get("hosts") or []):
            continue
        created = str(job.get("created_at", ""))
        if best_found is None or created > best_created:
            best_key, best_found, best_created = key, found, created
    if best_found is None:
        raise HTTPException(
            status_code=400,
            detail="no finished scan to verify against — run a scan first",
        )
    job_id, report = best_key, best_found
    res = store.record_watch_snapshot(engagement_id, report, source="verify")
    res["job_id"] = job_id
    return res


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


@router.get("/{engagement_id}/vault")
def loot_vault(engagement_id: str, reveal: bool = False) -> dict[str, Any]:
    """Masked loot vault: verified creds, flags, shares. reveal=true unmasks."""
    from services.loot_vault import vault_summary

    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    try:
        return vault_summary(store, engagement_id, reveal=reveal)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{engagement_id}/vault/export")
def loot_vault_export(
    engagement_id: str, fmt: str = "md", reveal: bool = False
) -> dict[str, Any]:
    """Masked vault export for handoff/reporting (json or markdown)."""
    from services.loot_vault import vault_markdown, vault_summary

    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    try:
        if fmt.lower() in ("json",):
            return vault_summary(store, engagement_id, reveal=reveal)
        return {
            "fmt": "md",
            "content": vault_markdown(store, engagement_id, reveal=reveal),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{engagement_id}/hygiene")
def credential_hygiene(engagement_id: str) -> dict[str, Any]:
    """Reuse/weak/default summary of verified credentials (read-only)."""
    from services.hygiene import hygiene_report

    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return hygiene_report(store, engagement_id)


@router.get("/{engagement_id}/graph")
def engagement_graph(engagement_id: str) -> dict[str, Any]:
    return get_store().graph(engagement_id)


@router.get("/{engagement_id}/graph/canvas")
def engagement_graph_canvas(engagement_id: str) -> dict[str, Any]:
    """Canvas-ready layout of the asset graph (feature 1: interactive canvas).

    Same topology as ``graph`` plus deterministic x/y per node so the UI
    can render pan/zoom SVG without a physics engine. Read-only.
    """
    from services.graph_canvas import layout_graph

    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    return layout_graph(store.graph(engagement_id))


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


@router.get("/{engagement_id}/flag-paths")
def flag_paths(
    engagement_id: str,
    max_depth: int = 6,
    limit: int = 25,
    fmt: str = "json",
) -> dict[str, Any]:
    """Evidence-backed paths from footholds to the hosts where flags fell.

    Same engine as attack-paths, but the objectives are the captured flags:
    one synthetic objective per flag host, with the flags attached to each
    path's final hop. Unplaced flags (no host recorded) are reported but
    cannot be pathed to. `fmt=md` returns a markdown writeup.
    """
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services.flag_paths import compute_flag_paths, flag_paths_to_markdown

    result = compute_flag_paths(store, engagement_id, max_depth=max_depth, limit=limit)
    if fmt.lower() in ("md", "markdown"):
        return {
            "fmt": "md",
            "content": flag_paths_to_markdown(result),
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


@router.get("/{engagement_id}/handoff/navigator")
def handoff_navigator(engagement_id: str) -> dict[str, Any]:
    """ATT&CK Navigator layer for this engagement's observed techniques."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services import blue_team
    from services.attck import enrich_engagement

    eng = store.get_engagement(engagement_id) or {}
    return blue_team.build_navigator_layer(
        enrich_engagement(store, engagement_id), eng.get("name", engagement_id)
    )


@router.get("/{engagement_id}/handoff/sigma")
def handoff_sigma(engagement_id: str) -> dict[str, Any]:
    """Experimental Sigma detections for observed techniques (tune before use)."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services import blue_team
    from services.attck import enrich_engagement

    eng = store.get_engagement(engagement_id) or {}
    enriched = enrich_engagement(store, engagement_id)
    rules = blue_team.build_sigma_bundle(enriched, eng.get("name", engagement_id))
    return {
        "format": "sigma-yaml",
        "count": len(rules),
        "rules": rules,
        "yaml": blue_team.rules_to_yaml(rules),
    }


@router.get("/{engagement_id}/handoff/summary")
def handoff_summary(engagement_id: str) -> dict[str, Any]:
    """Written defender handoff (markdown) for this engagement."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    from services import blue_team
    from services.attck import enrich_engagement

    eng = store.get_engagement(engagement_id) or {}
    return {
        "markdown": blue_team.defender_summary(
            enrich_engagement(store, engagement_id), eng.get("name", engagement_id)
        )
    }


@router.get("/{engagement_id}/propagate/plan")
def propagation_plan(
    engagement_id: str, max_per_user: int = 25, jitter_max: float = 0.0
) -> dict[str, Any]:
    """Dry run: blast radius before authorizing anything. No network calls."""
    store = get_store()
    if not store.get_engagement(engagement_id):
        raise HTTPException(status_code=404, detail="engagement not found")
    msf = _msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="metasploit client unavailable")
    return PropagationService(msf, store).plan(
        engagement_id, max_per_user=max_per_user, jitter_max=jitter_max
    )


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
    return svc.run(
        engagement_id,
        open_sessions=req.open_sessions,
        max_attempts=cap,
        max_per_user=req.max_per_user,
        jitter_max=req.jitter_max,
    )
