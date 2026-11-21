# Sandbox endpoints: inspect profiles and run an allowlisted tool inside one.
#
# Running arbitrary argv is deliberately admin-only and still constrained by the
# profile's allowlist and resource caps. This is not a shell: there is no
# interpreter wrapper, no inherited environment, and no implicit network.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services import approval, sandbox_exec as sandbox

logger = logging.getLogger("h4k.routers.sandbox")

router = APIRouter(prefix="/api/sandbox")


@router.get("/profiles")
def list_profiles() -> dict[str, Any]:
    return {
        "profiles": sandbox.profiles(),
        "sidecar": sandbox.SandboxRunner("recon").status()["mode"],
    }


@router.get("/status")
def sandbox_status(profile: str = "recon") -> dict[str, Any]:
    try:
        runner = sandbox.SandboxRunner(profile)
    except sandbox.SandboxError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return {**runner.status(), "active_profiles": sandbox.active_count()}


@router.get("/active")
def sandbox_active() -> dict[str, Any]:
    return {"active": sandbox.active_count()}


@router.post("/run")
def sandbox_run(body: dict[str, Any]) -> dict[str, Any]:
    """Run a tool under a profile. Body: {profile, argv, timeout_s?, stdin?, env?}."""
    profile = str((body or {}).get("profile") or "")
    argv = (body or {}).get("argv") or []
    if not isinstance(argv, list):
        raise HTTPException(status_code=400, detail="argv must be a list")
    timeout = (body or {}).get("timeout_s")
    try:
        runner = sandbox.SandboxRunner(profile)
        result = runner.run(
            [str(x) for x in argv],
            timeout=float(timeout) if timeout else None,
            stdin=str((body or {}).get("stdin") or ""),
            env=dict((body or {}).get("env") or {}),
            approval_id=str((body or {}).get("approval_id") or ""),
        )
    except approval.ApprovalRequired as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "approval required before this command can run",
                "request_id": exc.request_id,
                "decision": exc.decision,
            },
        ) from exc
    except approval.ApprovalDenied as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "command denied by approval policy",
                "decision": exc.decision,
            },
        ) from exc
    except sandbox.SandboxError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail=f"invalid run request: {exc}"
        ) from exc
    logger.info(
        "sandbox run profile=%s tool=%s rc=%s timed_out=%s",
        result.get("profile"),
        result.get("tool"),
        result.get("rc"),
        result.get("timed_out"),
    )
    return result
