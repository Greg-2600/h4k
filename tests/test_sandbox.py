"""Unit tests for sandbox mode: deterministic stand-ins for real tools.

Sandbox mode is what makes the Selenium suite (and CI) possible, so it gets
the same offline discipline as the rest of the test suite: no network, no
Metasploit daemon, no real tools.
"""

import pytest
from services import sandbox
from services.engagement import EngagementStore


@pytest.fixture()
def store(tmp_path):
    return EngagementStore(tmp_path / "engagements.db")


# ---- switch ---------------------------------------------------------------


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    assert sandbox.enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_enabled_values(monkeypatch, value):
    monkeypatch.setenv("H4K_SANDBOX", value)
    assert sandbox.enabled() is True


def test_disabled_values(monkeypatch):
    for value in ("", "0", "false", "no"):
        monkeypatch.setenv("H4K_SANDBOX", value)
        assert sandbox.enabled() is False


# ---- canned tool output ---------------------------------------------------


def test_nmap_xml_parses_with_the_real_parser(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    from routers.scan import _parse_nmap_xml

    parsed = _parse_nmap_xml(sandbox.nmap_xml("10.10.10.5"))
    assert len(parsed) == 1
    entry = parsed[0]
    assert entry["ip"] == "10.10.10.5"
    assert entry["hostname"] == "web01.lab"
    ports = {s["port"] for s in entry["services"] if s["state"] == "open"}
    assert ports == {22, 80}


def test_nmap_xml_for_unknown_host_is_empty_but_valid(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    from routers.scan import _parse_nmap_xml

    assert _parse_nmap_xml(sandbox.nmap_xml("10.10.10.99")) == []


def test_tool_result_nmap_and_hydra(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    nmap = sandbox.tool_result("nmap", ["nmap", "-oX", "-", "10.10.10.9"])
    assert nmap is not None
    assert nmap["status"] == "ok"
    assert "10.10.10.9" in nmap["stdout"]

    hydra = sandbox.tool_result("hydra", ["hydra", "-o", "-", "10.10.10.9", "ssh"])
    assert hydra is not None
    assert "login: admin" in hydra["stdout"]

    # a host with no known account yields nothing
    empty = sandbox.tool_result("hydra", ["hydra", "-o", "-", "10.10.10.42", "ssh"])
    assert empty["stdout"] == ""


def test_tool_result_unknown_tool_is_none(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    assert sandbox.tool_result("nikto", ["nikto", "-host", "http://x"]) is None


def test_hydra_output_matches_the_parsers_regex(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    import re

    out = sandbox.hydra_output("10.10.10.5")
    hits = re.findall(
        r"\[\d+\]\[[^\]]+\]\s*host:\s*([\d.]+)\s+login:\s+([^\s]+)\s+password:\s+([^\s]+)",
        out,
    )
    assert hits == [("10.10.10.5", "admin", "lab-admin")]


# ---- fake metasploit ------------------------------------------------------


def test_fake_msf_never_claims_a_successful_exploit():
    msf = sandbox.FakeMsfClient()
    res = msf.execute("exploit", "exploit/unix/ssh/x", {"RHOSTS": "10.10.10.5"})
    assert res["status"] == "failed"
    assert "sandbox" in res["error"].lower()
    mod = msf.modules.use("exploit", "exploit/unix/ssh/x")
    mod["RHOSTS"] = "10.10.10.5"
    assert mod.execute()["status"] == "failed"


def test_fake_msf_reports_a_version_and_empty_db():
    msf = sandbox.FakeMsfClient()
    assert "sandbox" in msf.core.version
    assert msf.hosts() == []
    assert msf.services() == []
    assert msf.vulns() == []
    assert msf.current_workspace() == "default"


def test_toolkit_runner_is_sandboxed(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner()
    res = runner.run_tool("nmap", ["nmap", "-oX", "-", "10.10.10.5"])
    assert res["status"] == "ok"
    assert "10.10.10.5" in res["stdout"]
    # unknown tools are refused instead of spawned
    res2 = runner.run_tool("nikto", ["nikto", "-host", "http://10.10.10.5"])
    assert res2["status"] == "sandbox"


def test_discovery_returns_the_canned_estate(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    from services.discovery import NeighborFinder

    finder = NeighborFinder(msf=sandbox.FakeMsfClient())
    found = finder.discover("10.10.10.0/24")
    assert {n.ip for n in found} == {"10.10.10.5", "10.10.10.9", "10.10.10.42"}


# ---- seeding --------------------------------------------------------------


def test_seed_engagement_populates_the_store(store):
    eng = sandbox.seed_engagement(store)
    assets = store.assets(eng["id"])
    assert len(assets) == 3
    creds = store.credentials(eng["id"])
    assert len(creds) == 2
    # the admin credential pivots across two hosts -> a real lateral path
    admin = next(c for c in creds if c["user"] == "admin")
    assert len(admin["hosts"]) == 2
    jewels = store.list_crown_jewels(eng["id"])
    assert len(jewels) == 1
    assert jewels[0]["host"] == "10.10.10.42"


def test_seeded_engagement_yields_attack_paths(store):
    from services.attack_paths import compute_attack_paths

    eng = sandbox.seed_engagement(store)
    res = compute_attack_paths(store, eng["id"])
    assert res["summary"]["paths"] >= 1
    path = res["paths"][0]
    assert path["crown_jewel_host"] == "10.10.10.42"
    assert path["nodes"][0] == "10.10.10.5"


def test_seeded_engagement_yields_attck_mappings(store):
    from services.attck import enrich_engagement

    eng = sandbox.seed_engagement(store)
    res = enrich_engagement(store, eng["id"])
    assert res["techniques"]
    assert any(t["id"].startswith("T") for t in res["techniques"])


def test_sandbox_scope_is_a_valid_cidr():
    import ipaddress

    assert ipaddress.ip_network(sandbox.sandbox_scope()).num_addresses == 256


def test_fake_msf_full_surface():
    """Exercise the remaining defensive branches of FakeMsfClient."""
    msf = sandbox.FakeMsfClient()
    assert msf.execute("exploit", "x", {})["status"] == "failed"
    assert msf.check("exploit", "x", {})["status"] == "failed"
    assert msf.call("db.hosts", []) == {"hosts": []}
    assert msf.call("db.services", []) == {"services": []}
    assert msf.call("db.vulns", []) == {"vulns": []}
    assert msf.call("something.else", []) == {}
    assert msf.hosts() == [] and msf.services() == [] and msf.vulns() == []
    assert msf.current_workspace() == "default"
    assert msf.report_host("10.0.0.1")["sandbox"] is True
    assert msf.analyze_host("10.0.0.1") == {"sandbox": True}
    assert msf.sessions() == {} and msf.jobs() == {} and msf.module_results("u") == {}
    assert msf.list_modules("auxiliary") == ["auxiliary/scanner/discovery/arp_sweep"]
    info = msf.get_module_info("auxiliary", "x")
    assert info["mtype"] == "auxiliary"
    assert msf.find_exploits(service="ssh") == []


def test_sandbox_tool_result_unknown_host_is_valid_xml(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    from routers.scan import _parse_nmap_xml

    out = sandbox.nmap_xml("192.0.2.1")
    assert _parse_nmap_xml(out) == []
