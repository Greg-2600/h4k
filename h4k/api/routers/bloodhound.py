# BloodHound CE endpoints (#92): login, collect, upload, analyze, Cypher.
#
# The client is stateful only in its bearer token. For a single-operator console
# a process-wide client is the right shape; credentials come from env or the
# explicit body and are never written to disk.
import logging
import threading
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException
from services.bloodhound_ce import QUERIES, BloodHoundClient, BloodHoundError

logger = logging.getLogger("h4k.routers.bloodhound")

router = APIRouter(prefix="/api/bloodhound")

_client: BloodHoundClient | None = None
_lock = threading.Lock()


def get_client(body: dict[str, Any] | None = None) -> BloodHoundClient:
    global _client
    body = body or {}
    with _lock:
        if _client is None or body.get("base_url") or body.get("username"):
            _client = BloodHoundClient(
                base_url=str(body.get("base_url") or ""),
                username=str(body.get("username") or ""),
                password=str(body.get("password") or ""),
                token=str(body.get("token") or ""),
            )
        return _client


def reset_client() -> None:
    global _client
    with _lock:
        _client = None


def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except BloodHoundError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _demand_engagement() -> None:
    """Collection uses domain credentials, so require an authorized engagement."""
    try:
        from routers.scan import _active_scope

        engagement_id, _store = _active_scope()
    except Exception:  # pragma: no cover - flat tests
        return
    if engagement_id is None:
        raise HTTPException(
            status_code=403,
            detail="BloodHound collection requires an active engagement scope",
        )


@router.get("/queries")
def bloodhound_queries() -> dict[str, Any]:
    return {"queries": {name: {"cypher": query} for name, query in QUERIES.items()}}


@router.get("/status")
def bloodhound_status() -> dict[str, Any]:
    return get_client().status()


@router.post("/login")
def bloodhound_login(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    return _call(client.login)


@router.post("/collect")
def bloodhound_collect(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    domain = str(body.get("domain") or "")
    username = str(body.get("username") or client.username)
    password = str(body.get("password") or client.password)
    if not domain or not username or not password:
        raise HTTPException(
            status_code=400, detail="domain, username and password are required"
        )
    _demand_engagement()
    return _call(
        client.collect,
        domain,
        username,
        password,
        dc_ip=str(body.get("dc_ip") or ""),
        method=str(body.get("method") or "All"),
    )


@router.post("/upload")
def bloodhound_upload(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    path = str(body.get("path") or "")
    if not path:
        raise HTTPException(
            status_code=400, detail="path to a collected zip is required"
        )
    return _call(client.upload_zip, path)


@router.post("/analyze")
def bloodhound_analyze(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    if body.get("wait"):
        return _call(
            client.wait_for_analysis,
            timeout=float(body.get("timeout") or 180),
            interval=float(body.get("interval") or 3),
        )
    return _call(client.start_analysis)


@router.get("/analysis")
def bloodhound_analysis_status() -> dict[str, Any]:
    return _call(get_client().analysis_status)


@router.post("/query")
def bloodhound_query(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    name = str(body.get("name") or "")
    if name:
        return _call(client.named_query, name)
    query = str(body.get("query") or "")
    if not query:
        raise HTTPException(status_code=400, detail="query or name is required")
    return _call(
        client.cypher, query, include_properties=bool(body.get("include_properties"))
    )


@router.post("/shortest-path")
def bloodhound_shortest_path(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    source = str(body.get("from") or body.get("source") or "")
    target = str(body.get("to") or body.get("target") or "")
    if not source or not target:
        raise HTTPException(status_code=400, detail="from and to are required")
    return _call(client.shortest_path, source, target)


@router.post("/collect-upload-analyze")
def bloodhound_full_loop(body: dict[str, Any]) -> dict[str, Any]:
    client = get_client(body)
    domain = str(body.get("domain") or "")
    username = str(body.get("username") or client.username)
    password = str(body.get("password") or client.password)
    if not domain or not username or not password:
        raise HTTPException(
            status_code=400, detail="domain, username and password are required"
        )
    _demand_engagement()
    return _call(
        client.collect_upload_analyze,
        domain,
        username,
        password,
        dc_ip=str(body.get("dc_ip") or ""),
        method=str(body.get("method") or "All"),
    )
