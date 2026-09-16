# Tests for the non-Metasploit toolkit plan and deep-attack request handling.
from schemas import DeepAttackRequest
from services.toolkit import ToolkitPlan, _has, _looks_domain


def test_toolkit_plan_for_ssh():
    req = DeepAttackRequest(target="10.0.0.5", host="10.0.0.5", services=["ssh"])
    plan = ToolkitPlan.for_target(req)
    tools = {p["tool"] for p in plan}
    assert "hydra" in tools


def test_toolkit_plan_for_http():
    req = DeepAttackRequest(target="10.0.0.5", host="10.0.0.5", services=["http"])
    plan = ToolkitPlan.for_target(req)
    tools = {p["tool"] for p in plan}
    assert {"nikto", "gobuster", "ffuf", "sqlmap"} <= tools


def test_toolkit_plan_for_smb():
    req = DeepAttackRequest(target="10.0.0.5", host="10.0.0.5", services=["smb"])
    plan = ToolkitPlan.for_target(req)
    tools = {p["tool"] for p in plan}
    assert {"smbmap", "smbclient"} <= tools


def test_toolkit_plan_picks_host():
    req = DeepAttackRequest(target="10.0.0.5", host="10.0.0.5", services=["ssh"])
    plan = ToolkitPlan.for_target(req)
    assert any("-L" in p["argv"] for p in plan if p["tool"] == "hydra")


def test_has_matches_substring():
    assert _has("ssh", ["ssh", "http"]) is True
    assert _has("smb", ["microsoft-ds"]) is True
    assert _has("dns", ["http"]) is False


def test_looks_domain():
    assert _looks_domain("example.com") is True
    assert _looks_domain("192.168.1.5") is False
    assert _looks_domain("") is False
