# Lab endpoints: the traffic kit (#87) and the IoT/OT pack (#90).
#
# Both are lab-only by construction: wire targets must resolve to loopback,
# RFC1918 or link-local addresses unless the caller sets allow_public, and when
# an engagement scope is active every resolved address must be inside it. The
# traffic kit is stateful (long-running jobs), the IoT pack is bounded and
# synchronous, so they share a router but not a lifecycle.
import logging
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from services import iot_ot, lab_traffic, wire

logger = logging.getLogger("h4k.routers.lab")

router = APIRouter(prefix="/api/lab")

_JOBS: dict[str, dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
_MAX_JOBS = 50


def _scope_check(host: str) -> None:
    """Reject a target if any resolved address is outside the active scope."""
    try:
        addresses = wire.resolve_host(host)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        from routers.scan import _host_in_scope
    except Exception:  # pragma: no cover - flat import in tests
        return
    for address in addresses:
        ok, reason = _host_in_scope(address)
        if not ok:
            raise HTTPException(status_code=403, detail=reason)


# ---------------------------------------------------------------------------
# Traffic kit
# ---------------------------------------------------------------------------
@router.get("/traffic/profiles")
def traffic_profiles() -> dict[str, Any]:
    return {"profiles": lab_traffic.profiles()}


@router.get("/traffic/jobs")
def traffic_jobs() -> dict[str, Any]:
    with _JOBS_LOCK:
        jobs = [
            {
                "id": job["id"],
                "status": job["status"],
                "profile": job["profile"],
                "target": job["target"],
                "created": job["created"],
                "summary": job.get("summary"),
            }
            for job in sorted(_JOBS.values(), key=lambda j: j["created"], reverse=True)
        ]
    return {"jobs": jobs}


@router.post("/traffic/run")
def traffic_run(body: dict[str, Any]) -> dict[str, Any]:
    profile = str((body or {}).get("profile") or "mixed")
    target = str((body or {}).get("target") or "")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    if profile not in lab_traffic.TRAFFIC_PROFILES:
        raise HTTPException(
            status_code=400, detail=f"unknown traffic profile: {profile}"
        )
    _scope_check(wire.parse_target(target).host)
    try:
        wire.check_lab_target(
            wire.parse_target(target).host,
            allow_public=bool((body or {}).get("allow_public")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    runner = lab_traffic.TrafficRunner(stop_event=threading.Event())
    kwargs = {
        "count": int((body or {}).get("count") or 20),
        "duration_s": float((body or {}).get("duration_s") or 0),
        "rate_per_s": float((body or {}).get("rate_per_s") or 2),
        "allow_public": bool((body or {}).get("allow_public")),
        "ports": [int(p) for p in ((body or {}).get("ports") or [])],
        "seed": (body or {}).get("seed"),
    }
    if (body or {}).get("wait"):
        try:
            return runner.run(profile, target, **kwargs)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    job: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "status": "running",
        "profile": profile,
        "target": target,
        "created": time.time(),
        "summary": None,
        "events": [],
        "error": "",
        "stop_event": runner.stop_event,
    }
    with _JOBS_LOCK:
        _JOBS[job["id"]] = job
        _prune_jobs()

    def _work() -> None:
        try:
            result = runner.run(profile, target, **kwargs)
            job["summary"] = result["summary"]
            job["events"] = result["events"]
            job["status"] = "stopped" if result["summary"]["stopped"] else "complete"
        except Exception as exc:
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["status"] = "error"
        finally:
            job.pop("stop_event", None)

    threading.Thread(target=_work, daemon=True).start()
    return {"job_id": job["id"], "status": "running"}


@router.get("/traffic/{job_id}")
def traffic_job(job_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="traffic job not found")
        return {k: v for k, v in job.items() if k != "stop_event"}


@router.post("/traffic/{job_id}/stop")
def traffic_stop(job_id: str) -> dict[str, Any]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="traffic job not found")
        event = job.get("stop_event")
    if event is not None:
        event.set()
    return {"job_id": job_id, "status": "stop_requested"}


def _prune_jobs() -> None:
    if len(_JOBS) <= _MAX_JOBS:
        return
    finished = [j for j in _JOBS.values() if j["status"] != "running"]
    finished.sort(key=lambda j: j["created"])
    for job in finished[: len(_JOBS) - _MAX_JOBS]:
        _JOBS.pop(job["id"], None)


# ---------------------------------------------------------------------------
# IoT / OT
# ---------------------------------------------------------------------------
@router.get("/iot/protocols")
def iot_protocols() -> dict[str, Any]:
    return {"protocols": iot_ot.PROTOCOLS, "read_only": True}


@router.post("/iot/probe")
def iot_probe(body: dict[str, Any]) -> dict[str, Any]:
    host = str((body or {}).get("host") or (body or {}).get("target") or "")
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    _scope_check(wire.parse_target(host, default_port=0).host)
    try:
        return iot_ot.probe(
            host,
            port=(body or {}).get("port"),
            protocol=str((body or {}).get("protocol") or "auto"),
            timeout=float((body or {}).get("timeout") or 2),
            allow_public=bool((body or {}).get("allow_public")),
            community=str((body or {}).get("community") or "public"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/iot/discover")
def iot_discover(body: dict[str, Any]) -> dict[str, Any]:
    host = str((body or {}).get("host") or (body or {}).get("target") or "")
    if not host:
        raise HTTPException(status_code=400, detail="host is required")
    _scope_check(wire.parse_target(host, default_port=0).host)
    try:
        return iot_ot.discover(
            host,
            protocols=(body or {}).get("protocols"),
            ports=(body or {}).get("ports"),
            timeout=float((body or {}).get("timeout") or 1.5),
            allow_public=bool((body or {}).get("allow_public")),
            community=str((body or {}).get("community") or "public"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
