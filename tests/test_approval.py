# Approval gate: rule matching, ask/deny/allow, request lifecycle, redaction,
# sandbox/toolkit integration and the API/UI contract. Offline.
from contextlib import asynccontextmanager
from pathlib import Path

import main as main_module
import pytest
from fastapi.testclient import TestClient
from services import approval, sandbox_exec as sandbox, toolkit


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("H4K_APPROVAL_MODE", "enforce")
    return approval.ApprovalStore(tmp_path / "approvals.db")


def _rule(store, pattern, action="ask", match_type="string", priority=100, name="r"):
    return store.add_rule(
        name,
        pattern,
        action=action,
        match_type=match_type,
        priority=priority,
    )


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def test_no_rule_allows_and_records_system_decision(store):
    decision = store.check(["echo", "hi"])
    assert decision["action"] == "allow"
    assert decision["decided_by"] == "system"
    assert store.decisions()[0]["action"] == "allow"


def test_string_regex_and_argv_prefix_matching(store):
    _rule(store, "hydra", "allow", priority=10, name="allow hydra")
    _rule(store, r"rm\s+-rf", "deny", match_type="regex", priority=1, name="no rm")
    _rule(store, ["nmap", "-sS"], "ask", match_type="argv_prefix", priority=20)

    assert store.check(["hydra", "-l", "a"])["decided_by"] == "rule"
    with pytest.raises(approval.ApprovalDenied):
        store.check(["rm", "-rf", "/"])
    with pytest.raises(approval.ApprovalRequired) as exc:
        store.check(["/usr/bin/nmap", "-sS", "10.0.0.5"])
    assert exc.value.request_id.startswith("Q-")


def test_rule_priority_first_match_and_disabled(store):
    _rule(store, "nmap", "deny", priority=1, name="deny first")
    _rule(store, "nmap", "allow", priority=50, name="allow later")
    with pytest.raises(approval.ApprovalDenied):
        store.check(["nmap", "-sT", "x"])

    rule = _rule(store, "masscan", "deny", priority=1, name="disabled")
    store.update_rule(rule["id"], {"enabled": False})
    assert store.check(["masscan", "x"])["action"] == "allow"


def test_rule_validation_and_crud(store):
    with pytest.raises(approval.ApprovalError):
        _rule(store, "", "ask")
    with pytest.raises(approval.ApprovalError):
        _rule(store, ["x"], "bogus")
    with pytest.raises(approval.ApprovalError):
        _rule(store, "x", "ask", match_type="glob")
    with pytest.raises(approval.ApprovalError):
        _rule(store, "not-json", "ask", match_type="argv_prefix")

    rule = _rule(store, ["hydra"], "ask", match_type="argv_prefix")
    assert rule["pattern"] == ["hydra"]
    updated = store.update_rule(rule["id"], {"action": "deny", "priority": 5})
    assert updated["action"] == "deny"
    assert store.delete_rule(rule["id"]) is True
    assert store.delete_rule(rule["id"]) is False


def test_ask_approve_retry_and_fingerprint(store):
    _rule(store, ["hydra"], "ask", match_type="argv_prefix")
    with pytest.raises(approval.ApprovalRequired) as exc:
        store.check(["hydra", "-l", "admin"])
    request_id = exc.value.request_id
    request = store.get_request(request_id)
    assert request["status"] == "pending"
    assert request["argv"] == ["hydra", "-l", "admin"]

    approved = store.approve(request_id, note="operator said yes")
    assert approved["status"] == "approved"
    decision = store.check(["hydra", "-l", "admin"], approval_id=request_id)
    assert decision["action"] == "allow"
    assert decision["decided_by"] == "human"

    # a different command cannot reuse the approval
    with pytest.raises(approval.ApprovalRequired):
        store.check(["hydra", "-l", "other"], approval_id=request_id)


def test_ask_deny_retry(store):
    _rule(store, ["hydra"], "ask", match_type="argv_prefix")
    with pytest.raises(approval.ApprovalRequired) as exc:
        store.check(["hydra", "-l", "admin"])
    request_id = exc.value.request_id
    store.deny(request_id, note="not in scope")
    with pytest.raises(approval.ApprovalDenied):
        store.check(["hydra", "-l", "admin"], approval_id=request_id)


def test_request_expiry(store, monkeypatch):
    _rule(store, ["hydra"], "ask", match_type="argv_prefix")
    with pytest.raises(approval.ApprovalRequired) as exc:
        store.check(["hydra", "x"])
    request_id = exc.value.request_id
    # force the request into the past
    import sqlite3

    conn = sqlite3.connect(store.path)
    conn.execute(
        "UPDATE requests SET created_at='2000-01-01T00:00:00+00:00' WHERE id=?",
        (request_id,),
    )
    conn.commit()
    conn.close()
    assert store.requests()[0]["status"] == "expired"
    with pytest.raises(approval.ApprovalRequired):
        store.check(["hydra", "x"], approval_id=request_id)


def test_redaction_in_requests_and_decisions(store):
    _rule(store, "hydra", "ask")
    with pytest.raises(approval.ApprovalRequired) as exc:
        store.check(["hydra", "-l", "admin", "-p", "S3cret", "-w", "other"])
    request = store.get_request(exc.value.request_id)
    assert "S3cret" not in request["argv"]
    assert request["argv"].count("[REDACTED]") == 2
    store.approve(exc.value.request_id)
    decision = store.check(
        ["hydra", "-l", "admin", "-p", "S3cret", "-w", "other"],
        approval_id=exc.value.request_id,
    )
    assert "S3cret" not in decision["argv"]
    assert all("S3cret" not in d["argv"] for d in store.decisions())


def test_audit_and_off_modes(store, monkeypatch):
    _rule(store, "hydra", "deny")
    monkeypatch.setenv("H4K_APPROVAL_MODE", "audit")
    decision = store.check(["hydra", "x"])
    assert decision["action"] == "allow"
    assert decision["matched_action"] == "deny"
    monkeypatch.setenv("H4K_APPROVAL_MODE", "off")
    decision = store.check(["hydra", "x"])
    assert decision["action"] == "allow"
    assert decision["reason"] == "approval gate off"


# ---------------------------------------------------------------------------
# Sandbox / toolkit integration
# ---------------------------------------------------------------------------
def _profile():
    return sandbox.SandboxProfile(
        name="gate-test",
        description="test",
        tools=("echo", "true"),
        runtime_s=5,
        max_output_kb=16,
    )


def test_sandbox_ask_then_approve(store, monkeypatch):
    monkeypatch.setattr(approval, "ApprovalStore", lambda *a, **k: store)
    _rule(store, ["echo"], "ask", match_type="argv_prefix")
    runner = sandbox.SandboxRunner(_profile())
    with pytest.raises(approval.ApprovalRequired) as exc:
        runner.run(["echo", "hello"])
    store.approve(exc.value.request_id)
    result = runner.run(["echo", "hello"], approval_id=exc.value.request_id)
    assert result["ok"] is True
    assert "hello" in result["stdout"]


def test_sandbox_deny_never_runs(store, monkeypatch):
    monkeypatch.setattr(approval, "ApprovalStore", lambda *a, **k: store)
    _rule(store, ["echo"], "deny", match_type="argv_prefix")
    with pytest.raises(approval.ApprovalDenied):
        sandbox.SandboxRunner(_profile()).run(["echo", "hello"])


def test_toolkit_deny_and_ask(store, monkeypatch):
    monkeypatch.setattr(approval, "ApprovalStore", lambda *a, **k: store)
    calls = []

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _run(argv, **kwargs):
        calls.append(argv)
        return _Proc()

    monkeypatch.setattr(toolkit.subprocess, "run", _run)
    runner = toolkit.ToolkitRunner()
    _rule(store, ["hydra"], "deny", match_type="argv_prefix")
    denied = runner.run_tool("hydra", ["hydra", "-l", "x"])
    assert denied["status"] == "denied"
    assert calls == []

    store.update_rule(store.rules()[0]["id"], {"action": "ask"})
    asked = runner.run_tool("hydra", ["hydra", "-l", "x"])
    assert asked["status"] == "approval_required"
    assert asked["approval_id"].startswith("Q-")
    store.approve(asked["approval_id"])
    ok = runner.run_tool(
        "hydra", ["hydra", "-l", "x"], approval_id=asked["approval_id"]
    )
    assert ok["status"] == "ok"
    assert calls


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app_state
    import routers.approvals as approvals_router

    class _CveStub:
        cves: tuple = ()
        path = "stub.json"

        def refresh(self) -> bool:
            return False

    app_state.msf_client = None
    app_state.cve_db = _CveStub()  # type: ignore[assignment]
    approvals_router._store = approval.ApprovalStore(tmp_path / "api-approvals.db")
    monkeypatch.setenv("H4K_APPROVAL_MODE", "enforce")

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    main_module.reset_auth_cache()
    monkeypatch.delenv("H4K_AUTH_ENABLED", raising=False)
    main_module.reset_auth_cache()
    yield TestClient(main_module.app)
    approvals_router.reset_store()
    main_module.reset_auth_cache()


def test_api_rules_check_and_approval_flow(client):
    status = client.get("/api/approvals/status").json()
    assert status["mode"] == "enforce"
    assert "allow" in status["actions"]

    rule = client.post(
        "/api/approvals/rules",
        json={
            "name": "ask hydra",
            "pattern": ["hydra"],
            "match_type": "argv_prefix",
            "action": "ask",
        },
    )
    assert rule.status_code == 200
    rule_id = rule.json()["id"]
    assert client.get("/api/approvals/rules").json()["rules"][0]["name"] == "ask hydra"

    check = client.post("/api/approvals/check", json={"argv": ["hydra", "-l", "x"]})
    assert check.status_code == 200
    body = check.json()
    assert body["action"] == "ask"
    assert body["http_status"] == 409
    request_id = body["request_id"]
    pending = client.get("/api/approvals/requests").json()
    assert pending["requests"][0]["id"] == request_id

    approved = client.post(
        f"/api/approvals/requests/{request_id}/approve", json={"note": "ok"}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"
    allow = client.post(
        "/api/approvals/check",
        json={"argv": ["hydra", "-l", "x"], "approval_id": request_id},
    ).json()
    assert allow["action"] == "allow"
    assert allow["decided_by"] == "human"
    assert client.get("/api/approvals/decisions").json()["decisions"]

    patched = client.patch(f"/api/approvals/rules/{rule_id}", json={"action": "deny"})
    assert patched.json()["action"] == "deny"
    denied = client.post("/api/approvals/check", json={"argv": ["hydra", "x"]}).json()
    assert denied["action"] == "deny"
    assert denied["http_status"] == 403
    assert client.delete(f"/api/approvals/rules/{rule_id}").status_code == 200


def test_api_validation_and_404(client):
    assert (
        client.post(
            "/api/approvals/rules", json={"name": "x", "pattern": ""}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/approvals/rules",
            json={"name": "x", "pattern": "x", "action": "nope"},
        ).status_code
        == 400
    )
    assert client.post("/api/approvals/check", json={}).status_code == 400
    assert client.post("/api/approvals/requests/Q-nope/approve").status_code == 400
    assert client.delete("/api/approvals/rules/A-nope").status_code == 404
    assert (
        client.patch(
            "/api/approvals/rules/A-nope", json={"action": "allow"}
        ).status_code
        == 404
    )


def test_api_denied_request(client):
    rule = client.post(
        "/api/approvals/rules",
        json={"name": "ask", "pattern": "nmap", "action": "ask"},
    ).json()
    check = client.post("/api/approvals/check", json={"argv": ["nmap", "x"]}).json()
    request_id = check["request_id"]
    denied = client.post(f"/api/approvals/requests/{request_id}/deny")
    assert denied.json()["status"] == "denied"
    verdict = client.post(
        "/api/approvals/check",
        json={"argv": ["nmap", "x"], "approval_id": request_id},
    ).json()
    assert verdict["action"] == "deny"
    assert client.delete(f"/api/approvals/rules/{rule['id']}").status_code == 200


def test_ui_contract_ids_exist():
    web = Path(__file__).resolve().parents[1] / "h4k" / "web"
    html = (web / "ops.html").read_text(encoding="utf-8")
    js = (web / "ops.js").read_text(encoding="utf-8")
    for ident in (
        "approvals-card",
        "appr-mode",
        "appr-rules-tbody",
        "appr-rules-empty",
        "appr-requests-tbody",
        "appr-requests-empty",
        "appr-decisions",
        "appr-output",
        "appr-name",
        "appr-match",
        "appr-pattern",
        "appr-action",
        "appr-priority",
        "appr-check-argv",
        "btn-appr-add-rule",
        "btn-appr-refresh",
        "btn-appr-check",
    ):
        assert f'id="{ident}"' in html, f"missing #{ident}"
    for ident in (
        "appr-mode",
        "appr-rules-tbody",
        "appr-requests-tbody",
        "appr-decisions",
        "appr-output",
        "btn-appr-add-rule",
        "btn-appr-refresh",
        "btn-appr-check",
    ):
        assert ident in js


def test_toolkit_full_output_not_truncated(monkeypatch):
    """XML consumers get the whole stdout; human output keeps the tail cap."""
    import services.toolkit as toolkit_mod

    class Proc:
        returncode = 0
        stdout = "x" * 12000
        stderr = ""

    monkeypatch.setenv("H4K_APPROVAL_MODE", "off")
    monkeypatch.setattr(toolkit_mod.subprocess, "run", lambda *a, **k: Proc())
    runner = toolkit_mod.ToolkitRunner()
    full = runner.run_tool(
        "nmap", ["nmap", "--version"], internal=True, full_output=True
    )
    assert len(full["stdout"]) == 12000
    capped = runner.run_tool("nmap", ["nmap", "--version"], internal=True)
    assert len(capped["stdout"]) == 4000
