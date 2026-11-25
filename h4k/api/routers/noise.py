# Target-noise governor endpoints: inspect/adjust the per-host pacing profile
# and get scanner-specific low-and-slow flags.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services import noise

logger = logging.getLogger("h4k.routers.noise")

router = APIRouter(prefix="/api/noise")


@router.get("/status")
def noise_status() -> dict[str, Any]:
    return noise.status()


@router.post("/profile")
def set_noise_profile(body: dict[str, Any] | None = None) -> dict[str, Any]:
    name = str((body or {}).get("profile") or "off")
    try:
        return noise.set_profile(name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/reset")
def reset_noise() -> dict[str, Any]:
    return noise.reset()


@router.get("/guidance")
def noise_guidance(tool: str = "") -> dict[str, Any]:
    return noise.guidance(tool)
