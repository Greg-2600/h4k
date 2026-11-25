# Active Directory endpoints (#91, #93): lockout-aware credential operations and
# a read-only domain audit. Every route is opt-in; the destructive primitives
# (spray, roast) default to a dry-run plan and require execute=true.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services.ad_attacks import (
    ADCredentialAttacks,
    ADTarget,
    asrep_roast,
    kerberoast,
    password_policy,
    spray,
)
from services.ad_audit import ADDomainAudit

logger = logging.getLogger("h4k.routers.ad")

router = APIRouter(prefix="/api/ad")


def _target(body: dict[str, Any]) -> ADTarget:
    try:
        return ADTarget(
            domain=str((body or {}).get("domain") or ""),
            dc_ip=str((body or {}).get("dc_ip") or (body or {}).get("dc") or ""),
            username=str((body or {}).get("username") or ""),
            password=str((body or {}).get("password") or ""),
            base_dn=str((body or {}).get("base_dn") or ""),
            timeout=float((body or {}).get("timeout") or 60),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _demand_scope(target: ADTarget) -> None:
    try:
        from routers.scan import _demand_scope as scan_demand_scope

        scan_demand_scope(target.dc_ip)
    except HTTPException:
        raise
    except Exception:  # pragma: no cover - flat test imports
        pass


def _demand_engagement_for_execution(body: dict[str, Any]) -> None:
    """State-changing AD work requires an authorized engagement, not just an IP."""
    if not (body or {}).get("execute"):
        return
    try:
        from routers.scan import _active_scope

        engagement_id, _store = _active_scope()
    except Exception:  # pragma: no cover - flat test imports
        return
    if engagement_id is None:
        raise HTTPException(
            status_code=403,
            detail="execute=true requires an active engagement scope",
        )


@router.post("/policy")
def ad_policy(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    return password_policy(target)


@router.post("/users")
def ad_users(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    limit = int((body or {}).get("limit") or 500)
    return ADCredentialAttacks().users(target, limit=limit)


@router.post("/asrep")
def ad_asrep(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    _demand_engagement_for_execution(body)
    users = (body or {}).get("users") or None
    return asrep_roast(target, users, execute=bool((body or {}).get("execute")))


@router.post("/kerberoast")
def ad_kerberoast(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    _demand_engagement_for_execution(body)
    return kerberoast(target, execute=bool((body or {}).get("execute")))


@router.post("/spray")
def ad_spray(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    _demand_engagement_for_execution(body)
    passwords = [str(p) for p in ((body or {}).get("passwords") or [])]
    if not passwords:
        raise HTTPException(status_code=400, detail="at least one password is required")
    users = [str(u) for u in ((body or {}).get("users") or [])]
    if not users:
        found = ADCredentialAttacks().users(target)
        users = [u["user"] for u in found.get("users", [])]
    return spray(
        target,
        users,
        passwords,
        execute=bool((body or {}).get("execute")),
        delay=float((body or {}).get("delay") or 1.5),
        force=bool((body or {}).get("force")),
        stop_on_success=bool((body or {}).get("stop_on_success")),
    )


@router.post("/audit")
def ad_audit(body: dict[str, Any]) -> dict[str, Any]:
    target = _target(body)
    _demand_scope(target)
    audit = ADDomainAudit()
    return audit.audit(
        target,
        include_smb=bool((body or {}).get("include_smb", True)),
        max_samples=int((body or {}).get("max_samples") or 10),
    )
