"""Offline API tests for the sandbox router (h4k/api/routers/sandbox.py).

Every endpoint is exercised through FastAPI's TestClient with auth disabled
and the app lifespan stubbed. Tool execution is replaced by a fake runner, so
no test spawns a real tool or reaches the sidecar.
"""

from collections.abc import Iterator
from contextlib import asynccontextmanager
from typing import Any

import main as main_module
import pytest
from fastapi.testclient import TestClient
from routers import sandbox as sandbox_router
from services import approval, sandbox_exec as sandbox


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    monkeypatch.delenv("H4K_SANDBOX_URL", raising=False)
    monkeypatch.delenv("H4K_SANDBOX_TOKEN", raising=False)

    @asynccontextmanager
    async def _noop(_app: Any) -> Iterator[None]:
        yield

    original = main_module.app.router.lifespan_context
    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    try:
        yield TestClient(main_module.app)
    finally:
        main_module.app.router.lifespan_context = original
        main_module.reset_auth_cache()


@pytest.fixture()
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace the one execution seam; record exactly what the router passed."""
    state: dict[str, Any] = {
        "calls": [],
        "error": None,
        "result": {
            "ok": True,
            "rc": 0,
            "tool": "echo",
            "profile": "recon",
            "timed_out": False,
        },
    }

    class _Runner:
        def __init__(self, profile: str) -> None:
            self.profile = profile

        def status(self) -> dict[str, Any]:
            return {
                "mode": "local",
                "profile": self.profile,
                "limits": {},
                "active": 0,
            }

        def run(
            self,
            argv: list[str],
            *,
            timeout: float | None = None,
            stdin: str = "",
            env: dict[str, str] | None = None,
            approval_id: str = "",
        ) -> dict[str, Any]:
            state["calls"].append(
                {
                    "profile": self.profile,
                    "argv": argv,
                    "timeout": timeout,
                    "stdin": stdin,
                    "env": env,
                    "approval_id": approval_id,
                }
            )
            if state["error"] is not None:
                raise state["error"]
            return state["result"]

    monkeypatch.setattr(sandbox_router.sandbox, "SandboxRunner", _Runner)
    return state


def test_profiles_lists_profiles_and_runner_mode(client: TestClient) -> None:
    response = client.get("/api/sandbox/profiles")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sidecar"] == "local"
    names = [profile["name"] for profile in body["profiles"]]
    assert "recon" in names and "full" in names


def test_profiles_reports_sidecar_mode(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("H4K_SANDBOX_URL", "http://sandbox-runner:9099")
    response = client.get("/api/sandbox/profiles")
    assert response.status_code == 200, response.text
    assert response.json()["sidecar"] == "sidecar"


def test_status_merges_active_profiles(
    client: TestClient,
    fake_runner: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sandbox_router.sandbox, "active_count", lambda: {"recon": 2})
    response = client.get("/api/sandbox/status", params={"profile": "web"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["profile"] == "web"
    assert body["active_profiles"] == {"recon": 2}


def test_status_unknown_profile_is_400(client: TestClient) -> None:
    response = client.get("/api/sandbox/status", params={"profile": "does-not-exist"})
    assert response.status_code == 400
    assert "unknown sandbox profile" in response.json()["detail"]


def test_active_returns_counts(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sandbox_router.sandbox, "active_count", lambda: {"web": 1})
    assert client.get("/api/sandbox/active").json() == {"active": {"web": 1}}


def test_run_rejects_non_list_argv(client: TestClient) -> None:
    response = client.post(
        "/api/sandbox/run", json={"profile": "recon", "argv": "echo"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "argv must be a list"


def test_run_rejects_unknown_profile(client: TestClient) -> None:
    response = client.post(
        "/api/sandbox/run", json={"profile": "nope", "argv": ["echo"]}
    )
    assert response.status_code == 400
    assert "unknown sandbox profile" in response.json()["detail"]


def test_run_passes_all_fields_and_returns_result(
    client: TestClient, fake_runner: dict[str, Any]
) -> None:
    response = client.post(
        "/api/sandbox/run",
        json={
            "profile": "web",
            "argv": ["echo", 7],
            "timeout_s": 12.5,
            "stdin": "hello",
            "env": {"TZ": "UTC"},
            "approval_id": "Q-1",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json() == fake_runner["result"]
    assert fake_runner["calls"] == [
        {
            "profile": "web",
            "argv": ["echo", "7"],
            "timeout": 12.5,
            "stdin": "hello",
            "env": {"TZ": "UTC"},
            "approval_id": "Q-1",
        }
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [("timeout_s", "not-a-number"), ("env", ["not", "a", "mapping"])],
)
def test_run_invalid_scalar_is_400(
    client: TestClient, fake_runner: dict[str, Any], field: str, value: Any
) -> None:
    response = client.post(
        "/api/sandbox/run",
        json={"profile": "recon", "argv": ["echo"], field: value},
    )
    assert response.status_code == 400
    assert response.json()["detail"].startswith("invalid run request:")
    assert fake_runner["calls"] == []


def test_run_approval_required_is_409(
    client: TestClient, fake_runner: dict[str, Any]
) -> None:
    fake_runner["error"] = approval.ApprovalRequired(
        {"request_id": "Q-42", "action": "ask", "reason": "operator approval"}
    )
    response = client.post(
        "/api/sandbox/run", json={"profile": "recon", "argv": ["nmap"]}
    )
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["request_id"] == "Q-42"
    assert detail["decision"]["action"] == "ask"
    assert "approval required" in detail["message"]


def test_run_approval_denied_is_403(
    client: TestClient, fake_runner: dict[str, Any]
) -> None:
    fake_runner["error"] = approval.ApprovalDenied(
        {"action": "deny", "reason": "policy"}
    )
    response = client.post(
        "/api/sandbox/run", json={"profile": "recon", "argv": ["nmap"]}
    )
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["decision"]["action"] == "deny"
    assert "denied" in detail["message"]


@pytest.mark.parametrize("status_code", [403, 429])
def test_run_sandbox_error_propagates_status(
    client: TestClient, fake_runner: dict[str, Any], status_code: int
) -> None:
    fake_runner["error"] = sandbox.SandboxError(
        "blocked by profile", status_code=status_code
    )
    response = client.post(
        "/api/sandbox/run", json={"profile": "recon", "argv": ["nmap"]}
    )
    assert response.status_code == status_code
    assert response.json()["detail"] == "blocked by profile"
