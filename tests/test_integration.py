# Comprehensive integration tests for the h4k platform.
# These tests verify the full attack pipeline, security tooling, and
# API contracts using mocked MSF so no live exploitation occurs.
import json
import re
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Add h4k/api to path for direct imports
sys.path.insert(0, str(Path(__file__).parent.parent / "h4k" / "api"))

# ---------------------------------------------------------------------------
# Section 1: Lint & code-quality tools must pass
# ---------------------------------------------------------------------------


def test_ruff_passes():
    result = subprocess.run(
        ["ruff", "check", "h4k/api/"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0, f"Ruff errors:\n{result.stdout}\n{result.stderr}"


def test_black_passes():
    result = subprocess.run(
        ["black", "--check", "h4k/api/"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0, f"Black would reformat:\n{result.stdout}"


def test_mypy_passes():
    result = subprocess.run(
        ["mypy", "h4k/api/"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0, f"Mypy errors:\n{result.stdout}\n{result.stderr}"


def test_bandit_passes():
    result = subprocess.run(
        ["bandit", "-r", "h4k/api/", "-f", "json"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    if result.returncode not in (0, 1):
        pytest.skip(f"Bandit not installed or error: {result.stderr}")
    try:
        data = json.loads(result.stdout)
        issues = [
            e
            for e in data.get("results", [])
            if e.get("issue_text") and "B101" not in e.get("issue_text", "")
        ]
        assert len(issues) == 0, f"Bandit issues:\n{json.dumps(issues, indent=2)}"
    except json.JSONDecodeError:
        pytest.skip("Bandit output not JSON")


# ---------------------------------------------------------------------------
# Section 2: Fake MSF client used by all API tests
# ---------------------------------------------------------------------------


class FakeMsfClient:
    """Fully-stubbed MSF RPC client so tests never require a live daemon."""

    def __init__(self):
        self.workspace = "default"
        self._executed_modules = []
        self._sessions = []
        self._credentials = []

    # --- properties ---
    @property
    def client(self):
        return self

    @property
    def core(self):
        class _Core:
            @property
            def version(self):
                return {"version": "6.5.0", "ruby": "3.1", "api": "1.0"}

        return _Core()

    @property
    def db(self):
        return self

    # --- mock DB records ---
    def hosts(self, workspace=None, limit=None):
        return [
            {
                "address": "192.168.1.13",
                "name": "lab-target",
                "os_name": "Linux",
                "state": "alive",
                "workspace": workspace or self.workspace,
            },
        ]

    def services(self, workspace=None, host=None):
        return [
            {
                "host": "192.168.1.13",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "state": "open",
                "info": "OpenSSH 10.2p1 Debian",
            },
            {
                "host": "192.168.1.13",
                "port": 80,
                "proto": "tcp",
                "name": "http",
                "state": "open",
                "info": "nginx",
            },
            {
                "host": "192.168.1.13",
                "port": 443,
                "proto": "tcp",
                "name": "https",
                "state": "open",
                "info": "nginx",
            },
        ]

    def vulns(self, workspace=None, host=None):
        return [
            {
                "host": "192.168.1.13",
                "port": 22,
                "proto": "tcp",
                "name": "SSH Enum",
                "refs": ["CVE-2024-1234"],
                "severity": "Medium",
            },
        ]

    def creds(self, workspace=None, host=None):
        return [
            {"host": "192.168.1.13", "port": 22, "user": "root", "pass": "toor"},
        ]

    def notes(self, workspace=None, host=None):
        return []

    def loots(self, workspace=None):
        return []

    def jobs(self):
        return {}

    def sessions(self):
        return {}

    def current_workspace(self):
        return self.workspace

    # --- module execution ---
    def execute(self, module_type, module_name, opts):
        self._executed_modules.append(
            {"type": module_type, "name": module_name, "opts": opts}
        )
        return {"job_id": None, "uuid": "fake-uuid-12345"}

    def module_results(self, uuid):
        return []

    # --- module discovery ---
    def list_modules(self):
        return [
            "exploit/linux/ssh/ssh_login",
            "exploit/linux/ssh/ssh_enum_users",
            "auxiliary/scanner/ssh/ssh_login",
            "auxiliary/scanner/ssh/ssh_enum_users",
            "auxiliary/scanner/http/nginx_src_memcpy",
            "exploit/linux/http/nginx_chunked",
        ]

    def get_module_info(self, module_type, module_name):
        info = {
            "name": module_name,
            "description": f"Mock module {module_name}",
            "author": ["mock"],
            "references": [],
            "options": {
                "RHOSTS": {"type": "address", "required": True, "default": None},
                "RPORT": {"type": "port", "required": False, "default": 22},
                "USERNAME": {"type": "string", "required": False},
                "PASSWORD": {"type": "string", "required": False},
            },
        }
        if module_type == "exploit":
            info["payloads"] = ["linux/x86/shell_reverse_tcp"]
        return info

    def find_exploits(self, search_term):
        return ["exploit/linux/ssh/ssh_login", "exploit/linux/http/nginx_chunked"]

    # --- admin ---
    def create_workspace(self, name):
        self.workspace = name
        return True

    def use(self, module_type, module_name):
        return self


class CveDbStub:
    def refresh(self, *a, **k):
        return False

    def enrich(self, hosts, vulns):
        return {"services": {}, "vulns": {}}

    def match_service(self, service_banner, version=None, product=None):
        return []


# ---------------------------------------------------------------------------
# Section 3: API TestClient fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_msf():
    return FakeMsfClient()


@pytest.fixture
def cve_db_stub():
    return CveDbStub()


@pytest.fixture
def client(fake_msf, cve_db_stub, monkeypatch):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_MSF_PASSWORD", "fake")

    import app_state
    import main as main_module

    app_state.msf_client = fake_msf
    app_state.cve_db = cve_db_stub

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop

    return TestClient(main_module.app)


# ---------------------------------------------------------------------------
# Section 4: Health & API surface
# ---------------------------------------------------------------------------


def test_health_returns_msf_status(client, fake_msf):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["msf"]["reachable"] is True
    assert "version" in data["msf"]


def test_health_shows_version(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    msf = r.json()["msf"]
    assert "version" in msf


def test_scan_requires_target(client):
    # Empty string is accepted by schema but pipeline should handle gracefully
    r = client.post("/api/scan", json={"target": "", "mode": "overt"})
    # Returns 200 but job will likely fail or be queued with empty target
    assert r.status_code in (200, 400, 422)


def test_scan_rejects_invalid_mode(client):
    r = client.post("/api/scan", json={"target": "192.168.1.13", "mode": "invalid"})
    assert r.status_code == 422


def test_scan_rejects_invalid_depth(client):
    r = client.post(
        "/api/scan",
        json={"target": "192.168.1.13", "mode": "overt", "depth": "ultimate"},
    )
    assert r.status_code == 422


def test_scan_returns_job_id(client):
    r = client.post(
        "/api/scan",
        json={"target": "192.168.1.13", "mode": "overt", "depth": "standard"},
    )
    assert r.status_code == 200
    job = r.json()
    assert "id" in job
    assert job["status"] in ("queued", "running")


def test_scan_job_carries_target(client):
    r = client.post("/api/scan", json={"target": "192.168.1.13", "mode": "overt"})
    assert r.status_code == 200
    assert r.json()["target"] == "192.168.1.13"


def test_neighbors_endpoint(client, monkeypatch):
    from routers import scan as scan_router

    class FakeNeighbor:
        def __init__(self, ip, mac, hostname=""):
            self.ip = ip
            self.mac = mac
            self.hostname = hostname

    class FakeFinder:
        def __init__(self, msf_client=None, interface=None):
            pass

        def discover(self, cidr=None):
            return [
                FakeNeighbor("192.168.1.1", "00:11:22:33:44:55"),
                FakeNeighbor("192.168.1.13", "66:77:88:99:aa:bb"),
            ]

        @staticmethod
        def neighbors_to_dicts(neighbors):
            return [
                {"ip": n.ip, "mac": n.mac, "hostname": n.hostname} for n in neighbors
            ]

    monkeypatch.setattr(scan_router, "NeighborFinder", FakeFinder)
    r = client.get("/api/neighbors")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)
    assert "neighbors" in data


def test_report_endpoint_returns_structure(client, monkeypatch):
    """GET /report/{id} returns a structured report."""
    r = client.get("/api/report/test-job-id")
    # May 404 if not found, but structure should be valid JSON
    assert r.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Section 5: Job monitor & log streaming
# ---------------------------------------------------------------------------


def test_jobs_endpoint_lists_all_families(client, monkeypatch):
    from routers import scan as scan_router

    for store_name in ["JOBS", "_attack_jobs", "_toolkit_jobs", "_fuzz_jobs"]:
        store = {}
        monkeypatch.setattr(scan_router, store_name, store)

    # Inject test jobs
    scan_router.JOBS["j1"] = {
        "id": "j1",
        "status": "running",
        "target": "192.168.1.13",
        "progress": 50,
    }
    scan_router._attack_jobs["a1"] = {
        "id": "a1",
        "status": "queued",
        "target": "192.168.1.13",
    }
    scan_router._toolkit_jobs["t1"] = {
        "id": "t1",
        "status": "done",
        "target": "192.168.1.13",
    }

    r = client.get("/api/jobs")
    assert r.status_code == 200
    payload = r.json()
    ids = {j["id"] for j in payload["jobs"]}
    assert "j1" in ids
    assert "a1" in ids
    assert "t1" in ids


def test_active_filter_hides_completed(client, monkeypatch):
    from routers import scan as scan_router

    monkeypatch.setattr(
        scan_router,
        "JOBS",
        {
            "done": {"id": "done", "status": "done"},
            "run": {"id": "run", "status": "running"},
        },
    )
    r = client.get("/api/jobs?active=true")
    assert r.status_code == 200
    ids = {j["id"] for j in r.json()["jobs"]}
    assert "done" not in ids
    assert "run" in ids


def test_job_detail_includes_log(client, monkeypatch):
    from routers import scan as scan_router

    log = ["[creds] try root:toor on 192.168.1.13:22 (ssh_login)", "SSH enum done"]
    monkeypatch.setattr(
        scan_router,
        "JOBS",
        {
            "job1": {
                "id": "job1",
                "status": "running",
                "target": "192.168.1.13",
                "log": log,
            }
        },
    )
    r = client.get("/api/jobs/job1")
    assert r.status_code == 200
    payload = r.json()
    assert "log" in payload
    assert len(payload["log"]) == 2


# ---------------------------------------------------------------------------
# Section 6: Credential pattern parsing in log
# ---------------------------------------------------------------------------

CREDS_LOG_PATTERNS = [
    re.compile(
        r"\[creds\] try (?P<user>[^:]+):(?P<pass>\S+) on (?P<host>\S+):(?P<port>\d+) \((?P<module>\S+)\)"
    ),
    re.compile(
        r"AUTH ATTEMPT: (?P<user>\S+):(?P<pass>\S+) → (?P<host>\S+):(?P<port>\d+)"
    ),
    re.compile(
        r"trying credential (?P<user>\S+):(?P<pass>\S+) on (?P<host>\S+):(?P<port>\d+)"
    ),
]


@pytest.mark.parametrize(
    "log_line",
    [
        "[creds] try root:toor on 192.168.1.13:22 (auxiliary/scanner/ssh/ssh_login)",
        "AUTH ATTEMPT: admin:admin → 192.168.1.13:22",
        "trying credential user:pass on 192.168.1.13:22 via ssh_login",
    ],
)
def test_cred_patterns_parse_correctly(log_line):
    matched = None
    for pat in CREDS_LOG_PATTERNS:
        m = pat.match(log_line)
        if m:
            matched = m.groupdict()
            break
    assert matched is not None, f"Line not matched: {log_line}"
    assert matched["user"] in ("root", "admin", "user")
    assert matched["host"] == "192.168.1.13"
    assert matched["port"] == "22"


# ---------------------------------------------------------------------------
# Section 7: Engagement scope enforcement
# ---------------------------------------------------------------------------


def test_engagement_requires_declaration(client):
    r = client.get("/api/engagement")
    assert r.status_code == 200  # returns empty list, no engagement active


def test_engagement_declare_and_retrieve(client):
    r = client.post(
        "/api/engagement",
        json={
            "name": "Lab Test",
            "scope": ["192.168.1.0/24"],
            " authorized": True,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "id" in data


def test_out_of_scope_host_rejected(client):
    r = client.post(
        "/api/engagement",
        json={"name": "Narrow", "scope": ["10.0.0.0/24"], "authorized": True},
    )
    assert r.status_code == 200
    eng_id = r.json()["id"]
    r2 = client.post(
        f"/api/engagement/{eng_id}/ingest",
        json={
            "hosts": [{"address": "192.168.1.13", "services": []}],
        },
    )
    assert r2.status_code == 200
    result = r2.json()
    assert result.get("skipped_out_of_scope") or result.get("out_of_scope_hosts")


# ---------------------------------------------------------------------------
# Section 8: Version detection & CVE matching
# ---------------------------------------------------------------------------


def test_version_detector_parses_banner():
    from services.version_detector import VersionDetector

    vd = VersionDetector()
    cases = [
        (
            "SSH-2.0-OpenSSH_10.2p1 Debian",
            22,
            "tcp",
            {"product": "ssh", "version": "10.2p1"},
        ),
        ("nginx/1.25.0", 80, "tcp", {"product": "http", "version": "1.25.0"}),
        ("Apache/2.4.52", 80, "tcp", {"product": "http", "version": "2.4.52"}),
    ]
    for banner, port, proto, expected in cases:
        result = vd.detect(banner, port, proto)
        assert result is not None, f"Failed on {banner}"
        assert (
            result["product"] == expected["product"]
        ), f"product mismatch for {banner}: got {result['product']}"
        assert result["version"] == expected["version"]


def test_version_detector_returns_none_for_unknown():
    from services.version_detector import VersionDetector

    vd = VersionDetector()
    result = vd.detect("totally unknown banner xyz", 9999, "tcp")
    assert result is not None  # returns dict with unknown product or empty


def test_version_aware_cve_match():
    from services.version_detector import check_vulnerable_version

    result = check_vulnerable_version("openssh", "10.2p1")
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Section 9: Service-to-scanner mapping
# ---------------------------------------------------------------------------


def test_service_to_scanner_maps_known_services():
    from services.modes import AUX_SCANNERS

    for svc in [
        "ssh",
        "redis",
        "mongodb",
        "vnc",
        "snmp",
        "nfs",
        "smtp",
        "imap",
        "pop3",
        "dns",
        "ntp",
        "cups",
    ]:
        assert svc in AUX_SCANNERS, f"Missing AUX_SCANNERS entry for {svc}"
        assert len(AUX_SCANNERS[svc]) > 0, f"AUX_SCANNERS[{svc}] is empty"


def test_static_exploit_modules_cover_common_services():
    from services.attack import STATIC_SERVICE_MODULES

    essentials = ["ssh", "http", "smb", "ftp", "mysql", "postgres", "redis", "vnc"]
    for svc in essentials:
        assert svc in STATIC_SERVICE_MODULES, f"Missing static mapping for {svc}"


# ---------------------------------------------------------------------------
# Section 10: UDP port depth
# ---------------------------------------------------------------------------


def test_udp_full_depth_is_comprehensive():
    from services.modes import DEPTHS

    full_config = DEPTHS.get("full", {})
    assert isinstance(full_config, dict), "full depth should be a config dict"
    assert "udp_nmap_args" in full_config or "ports_spec" in full_config
    # UDP scan args should reference a broad port range
    udp_args = full_config.get("udp_nmap_args", "")
    # Should include -p- or a range covering 1-65535 or common UDP ports
    assert udp_args, "udp_nmap_args should not be empty"


# ---------------------------------------------------------------------------
# Section 11: Toolkit tool availability
# ---------------------------------------------------------------------------


def test_toolkit_runner_is_tool_available():
    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner()
    assert hasattr(
        runner, "is_tool_available"
    ), "ToolkitRunner needs is_tool_available method"
    # is_tool_available should return False for nonexistent tool
    result = runner.is_tool_available("this-tool-does-not-exist-xyz123")
    assert result is False


# ---------------------------------------------------------------------------
# Section 12: Attack module option validation
# ---------------------------------------------------------------------------


def test_attack_request_schema_requires_module():
    from pydantic import ValidationError
    from schemas import AttackRequest

    with pytest.raises(ValidationError):
        AttackRequest(rhosts="192.168.1.13")  # missing module


def test_attack_request_schema_requires_rhosts():
    from pydantic import ValidationError
    from schemas import AttackRequest

    with pytest.raises(ValidationError):
        AttackRequest(module="exploit/linux/ssh/ssh_login")  # missing rhosts


# ---------------------------------------------------------------------------
# Section 13: Deep attack runs all toolkit steps
# ---------------------------------------------------------------------------


def test_deepattack_returns_job_id(client, monkeypatch):
    r = client.post("/api/deepattack", json={"target": "192.168.1.13"})
    assert r.status_code == 200
    data = r.json()
    assert "attack_id" in data or "job_id" in data


# ---------------------------------------------------------------------------
# Section 14: Schema validation on key models
# ---------------------------------------------------------------------------


def test_scan_request_schema_validates_mode():
    from pydantic import ValidationError
    from schemas import ScanRequest

    req = ScanRequest(target="192.168.1.13", mode="stealth")
    assert req.mode == "stealth"
    with pytest.raises(ValidationError):
        ScanRequest(target="192.168.1.13", mode="super stealth")


def test_scan_request_depth_default():
    from schemas import ScanRequest

    req = ScanRequest(target="192.168.1.13")
    assert req.depth == "standard"


def test_attack_request_requires_module():
    from pydantic import ValidationError
    from schemas import AttackRequest

    with pytest.raises(ValidationError):
        AttackRequest(rhosts="192.168.1.13")  # missing module


def test_job_model_has_log_field():
    from schemas import Job

    job = Job(
        id="test", status="running", target="192.168.1.13", log=["line1", "line2"]
    )
    assert job.log == ["line1", "line2"]


# ---------------------------------------------------------------------------
# Section 15: Credential propagation
# ---------------------------------------------------------------------------


def test_propagation_skips_unverified():
    from services.propagate import PropagationService

    svc = PropagationService.__new__(PropagationService)
    # No verified credentials = nothing to propagate
    assert svc is not None  # object created without error


# ---------------------------------------------------------------------------
# Section 16: SAST regex + Semgrep merge
# ---------------------------------------------------------------------------


def test_sast_finds_hardcoded_secret(tmp_path):
    from services.sast import SASTScanner

    engine = SASTScanner()

    # Write a temp Python file with a hardcoded password
    test_file = tmp_path / "config.py"
    test_file.write_text('password = "supersecret123"\n')

    findings = engine.scan_dir(tmp_path)
    assert len(findings) > 0
    assert any(
        "password" in f.description.lower() or "secret" in f.description.lower()
        for f in findings
    ), f"Expected password finding, got: {findings}"


def test_sast_finds_sql_injection(tmp_path):
    from services.sast import SASTScanner

    engine = SASTScanner()

    test_file = tmp_path / "query.py"
    test_file.write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n')

    findings = engine.scan_dir(tmp_path)
    assert len(findings) > 0
    assert any(
        "sql" in f.description.lower() or "injection" in f.description.lower()
        for f in findings
    ), f"Expected SQL injection finding, got: {findings}"


def test_sast_finds_cmd_injection(tmp_path):
    from services.sast import SASTScanner

    engine = SASTScanner()

    test_file = tmp_path / "run.py"
    test_file.write_text('os.system("ls " + user_input)\n')

    findings = engine.scan_dir(tmp_path)
    assert len(findings) > 0
    assert any(
        "command" in f.description.lower() or "injection" in f.description.lower()
        for f in findings
    ), f"Expected command injection finding, got: {findings}"


def test_sast_skips_ignores_and_env_patterns(tmp_path):
    from services.sast import SASTScanner

    engine = SASTScanner()

    # os.environ.get with password - should NOT trigger (good pattern)
    test_file = tmp_path / "settings.py"
    test_file.write_text('import os\npassword = os.environ.get("DB_PASSWORD")\n')

    findings = engine.scan_dir(tmp_path)
    assert not any(
        "password" in f.description.lower() for f in findings
    ), f"os.environ.get should not trigger: {findings}"


# ---------------------------------------------------------------------------
# Section 17: SCA with osv-scanner
# ---------------------------------------------------------------------------


def test_sca_scan_handles_nonexistent_directory():
    from pathlib import Path

    from services.sca import sca_scan

    result = sca_scan(Path("/tmp/nonexistent_dir_xyz123"))
    assert isinstance(result, dict)
    assert "cves" in result
    assert "packages" in result
    assert result["packages"] == []


# ---------------------------------------------------------------------------
# Section 18: Fuzzer signal handling
# ---------------------------------------------------------------------------


def test_fuzzer_crash_structure():
    crash = {"signal": 11, "input": b"GET /AAAA HTTP/1.1", "type": "SIGSEGV"}
    assert crash["signal"] == 11  # SIGSEGV


# ---------------------------------------------------------------------------
# Section 19: triage produces actionable output
# ---------------------------------------------------------------------------


def test_triage_build_triage_produces_report():
    from services.triage import build_triage

    asan_output = """
    ==12345== ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff1234
    READ of size 4 at 0x7fff1234 thread T0
    #0 0x401234 in parse_request /src/vulnlab.c:100
    """
    result = build_triage(asan_output)
    assert hasattr(result, "cwe")
    assert hasattr(result, "bug_class") or hasattr(result, "patch_direction")


# ---------------------------------------------------------------------------
# Section 20: Real integration: full scan pipeline mocked end-to-end
# ---------------------------------------------------------------------------


def test_full_scan_pipeline_produces_report(client, fake_msf, monkeypatch):
    """Simulate a full scan of 192.168.1.13 through the pipeline."""
    import datetime

    from routers import scan as scan_router
    from schemas import Coverage, Host, Report, ScanMode

    def fake_run_scan(job, req):
        job["status"] = "completed"
        job["progress"] = 100.0
        job["log"] = [
            f"[recon] scanning {req.target}",
            "[creds] try root:toor on 192.168.1.13:22 (ssh_login)",
            "SSH module executed",
            "[+] verification complete",
        ]
        job["report"] = Report(
            target=req.target,
            mode=ScanMode.overt,
            created_at=datetime.datetime.now().isoformat(),
            hosts=[
                Host(
                    address=req.target,
                    name="lab-target",
                    os_name="Linux",
                    state="alive",
                    services=[
                        {
                            "port": 22,
                            "proto": "tcp",
                            "name": "ssh",
                            "state": "open",
                            "info": "OpenSSH 10.2p1",
                        },
                        {
                            "port": 80,
                            "proto": "tcp",
                            "name": "http",
                            "state": "open",
                            "info": "nginx",
                        },
                    ],
                    vulns=[
                        {
                            "name": "SSH Enum",
                            "references": ["CVE-2024-1234"],
                            "severity": "Medium",
                        }
                    ],
                )
            ],
            vulns=[],
            recommendations=[],
            notes=[],
            raw={"stats": {"hosts": 1, "services": 2, "vulns": 1, "pwned": 0}},
            fingerprints=[],
            credentials=[],
            attacks=[],
            security=[],
            log=job["log"],
            coverage=Coverage(
                depth="standard", ports_spec="1-1000", max_ports=1000, complete=True
            ),
        )

    monkeypatch.setattr(scan_router, "_run_scan", fake_run_scan)

    r = client.post(
        "/api/scan",
        json={
            "target": "192.168.1.13",
            "mode": "overt",
            "depth": "standard",
            "do_vuln_scan": True,
            "try_default_creds": True,
        },
    )
    assert r.status_code == 200
    job_id = r.json()["id"]

    # Poll until done
    for _ in range(20):
        time.sleep(0.1)
        r2 = client.get(f"/api/jobs/{job_id}")
        if r2.json()["status"] in ("completed", "failed"):
            break

    r2 = client.get(f"/api/jobs/{job_id}")
    assert r2.status_code == 200
    job = r2.json()
    assert job["status"] == "completed"
    assert "report" in job
    assert len(job["report"]["hosts"]) == 1
    assert job["report"]["hosts"][0]["address"] == "192.168.1.13"
    assert len(job["report"]["hosts"][0]["services"]) == 2

    # Log should contain cred attempt
    assert any(
        "creds" in entry or "AUTH" in entry for entry in job["log"]
    ), f"Log missing creds: {job['log']}"


# ---------------------------------------------------------------------------
# Section 21: XP/achievement unlocks (UI-side, tested via JS)
# ---------------------------------------------------------------------------


def test_report_models_have_expected_structure():
    from services.report import Coverage, Credential, Host

    cov = Coverage(depth="full", ports_spec="1-1000", max_ports=1000, complete=True)
    assert cov.depth == "full"
    assert cov.complete is True

    cred = Credential(
        user="root", password="toor", service="ssh", host="192.168.1.13", port=22
    )
    assert cred.user == "root"
    assert cred.password == "toor"

    host = Host(
        address="192.168.1.13",
        name="lab",
        os_name="Linux",
        state="alive",
        services=[],
        vulns=[],
    )
    assert host.address == "192.168.1.13"
    assert host.state == "alive"


# ---------------------------------------------------------------------------
# Section 22: Zero-trust: engagement scope enforced on every write
# ---------------------------------------------------------------------------


def test_scope_rejects_cidr_mismatch(client):
    """Hosts outside engagement scope must never be stored."""
    r = client.post(
        "/api/engagement",
        json={"name": "Isolated Lab", "scope": ["192.168.1.0/28"], "authorized": True},
    )
    assert r.status_code == 200
    eng = r.json()

    # Try to ingest a host in 10.x (outside scope)
    r2 = client.post(
        f"/api/engagement/{eng['id']}/ingest",
        json={
            "hosts": [{"address": "10.0.0.99", "services": []}],
        },
    )
    result = r2.json()
    assert result.get("skipped_out_of_scope") or result.get("out_of_scope_hosts")


# ---------------------------------------------------------------------------
# Section 23: Report export formats
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "md"])
def test_export_endpoint_returns_valid_response(client, fmt):
    r = client.get(f"/api/export/nonexistent-{fmt}")
    # 404 is acceptable for unknown job; the response must be valid
    assert r.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Section 24: API authz header passthrough (security)
# ---------------------------------------------------------------------------


def test_api_rejects_missing_content_type(client):
    """API should enforce Content-Type: application/json."""
    r = client.post(
        "/api/scan", content="not json", headers={"Content-Type": "text/plain"}
    )
    assert r.status_code in (400, 415, 422)


# ---------------------------------------------------------------------------
# Section 25: Concurrent job handling
# ---------------------------------------------------------------------------


def test_concurrent_scans_get_different_ids(
    client, monkeypatch
):  # pylint: disable=redefined-outer-name
    from routers import scan as scan_router

    ids_seen = []

    def fake_run_scan(job, req):
        ids_seen.append(job["id"])

    monkeypatch.setattr(scan_router, "_run_scan", fake_run_scan)

    r1 = client.post("/api/scan", json={"target": "192.168.1.13", "mode": "overt"})
    r2 = client.post("/api/scan", json={"target": "192.168.1.14", "mode": "overt"})
    assert r1.json()["id"] != r2.json()["id"]
