# Approval policy endpoints: rules, pending requests, decisions and a dry-run
# check. Reads are viewer-level; rule/approval writes are operator-level.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services.approval import (
    ACTIONS,
    MATCH_TYPES,
    MODES,
    ApprovalDenied,
    ApprovalError,
    ApprovalRequired,
    ApprovalStore,
)

logger = logging.getLogger("h4k.routers.approvals")

router = APIRouter(prefix="/api/approvals")

_store: ApprovalStore | None = None


def get_store() -> ApprovalStore:
    global _store
    if _store is None:
        _store = ApprovalStore()
    return _store


def reset_store() -> None:
    global _store
    _store = None


@router.get("/status")
def approval_status() -> dict[str, Any]:
    return {
        **get_store().status(),
        "actions": list(ACTIONS),
        "match_types": list(MATCH_TYPES),
        "modes": list(MODES),
    }


@router.get("/rules")
def list_rules() -> dict[str, Any]:
    return {"rules": get_store().rules(), "match_types": list(MATCH_TYPES)}


@router.post("/rules")
def add_rule(body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = body or {}
    try:
        return get_store().add_rule(
            str(data.get("name") or ""),
            data.get("pattern") or "",
            action=str(data.get("action") or "ask"),
            match_type=str(data.get("match_type") or "string"),
            priority=int(data.get("priority") or 100),
            enabled=bool(data.get("enabled", True)),
        )
    except (ApprovalError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = dict(body or {})
    if isinstance(data.get("pattern"), list):
        data["match_type"] = "argv_prefix"
        import json

        data["pattern"] = json.dumps(data["pattern"])
    try:
        return get_store().update_rule(rule_id, data)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="rule not found") from exc
    except (ApprovalError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, Any]:
    if not get_store().delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="rule not found")
    return {"status": "deleted", "id": rule_id}


@router.get("/requests")
def list_requests(status: str = "pending", limit: int = 100) -> dict[str, Any]:
    return {"requests": get_store().requests(status, limit=limit)}


@router.post("/requests/{request_id}/approve")
def approve_request(
    request_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    data = body or {}
    try:
        return get_store().approve(
            request_id,
            decided_by=str(data.get("decided_by") or "human"),
            note=str(data.get("note") or ""),
        )
    except ApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/requests/{request_id}/deny")
def deny_request(request_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = body or {}
    try:
        return get_store().deny(
            request_id,
            decided_by=str(data.get("decided_by") or "human"),
            note=str(data.get("note") or ""),
        )
    except ApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/decisions")
def list_decisions(limit: int = 200) -> dict[str, Any]:
    decisions = get_store().decisions(limit=limit)
    return {"decisions": decisions, "count": len(decisions)}


@router.post("/check")
def check_command(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dry-run the policy for a command without executing it."""
    data = body or {}
    argv = data.get("argv")
    if not isinstance(argv, list) or not argv:
        raise HTTPException(status_code=400, detail="argv must be a non-empty list")
    try:
        return get_store().check(
            [str(a) for a in argv],
            tool=str(data.get("tool") or ""),
            approval_id=str(data.get("approval_id") or ""),
            context=dict(data.get("context") or {}),
        )
    except ApprovalDenied as exc:
        return {**exc.decision, "http_status": 403}
    except ApprovalRequired as exc:
        return {**exc.decision, "http_status": 409}
    except ApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
