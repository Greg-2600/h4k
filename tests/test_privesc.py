"""h4k knows the docker-group-to-root and userns-root paths and can try them.

Detection (docker_group_report) is read-only; the tries
(try_docker_group_read / try_userns_root) are explicit, read-only and
disabled in sandbox mode. The userns try uses no sudo and no docker.
"""

import os
from pathlib import Path

import pytest
from services import privesc as privesc_mod
from services.capabilities import build_report
from services.container_escape import ContainerEscape

# GitHub runners have passwordless sudo + docker by design, and ad-hoc test
# containers (/.dockerenv) are not hardened lab hosts either: these
# live-host hardening assertions only hold on a hardened lab host.
needs_hardened_host = pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") == "true" or Path("/.dockerenv").exists(),
    reason="needs hardened host (no passwordless sudo/docker); CI runners and test containers have both",
)


def test_privilege_report_shape():
    rep = privesc_mod.docker_group_report()
    for key in (
        "euid",
        "is_root",
        "in_container",
        "docker_groups",
        "docker_reachable_without_sudo",
        "direct_root_read",
        "vectors",
        "at_risk",
    ):
        assert key in rep


def test_privilege_report_marks_docker_group_vector(monkeypatch):
    monkeypatch.setattr(privesc_mod, "_euid", lambda: 1000)
    monkeypatch.setattr(privesc_mod, "_in_container", lambda: False)
    monkeypatch.setattr(privesc_mod, "_docker_groups", lambda: ["docker"])
    monkeypatch.setattr(privesc_mod, "_docker_works", lambda timeout=5.0: (True, "ok"))
    monkeypatch.setattr(
        privesc_mod, "_direct_root_read", lambda: (False, "Permission denied")
    )
    rep = privesc_mod.docker_group_report()
    assert rep["at_risk"] is True
    assert any(v["type"] == "docker-group" for v in rep["vectors"])


def test_capabilities_includes_privilege_section(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    report = build_report(None, use_cache=False)
    assert "privilege" in report
    assert "vectors" in report["privilege"]


def test_capabilities_warns_on_docker_group_risk(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    # build_report imports docker_group_report at call time from privesc,
    # so stubbing the privesc symbol is enough.
    monkeypatch.setattr(
        privesc_mod,
        "docker_group_report",
        lambda: {
            "euid": 1000,
            "is_root": False,
            "docker_groups": ["docker"],
            "docker_reachable_without_sudo": True,
            "at_risk": True,
            "vectors": [{"type": "docker-group"}],
        },
    )
    report = build_report(None, use_cache=False)
    assert any("docker group" in w for w in report["warnings"])


def test_try_docker_is_disabled_in_sandbox(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    out = privesc_mod.try_docker_group_read()
    assert out["success"] is False
    assert "sandbox" in out["reason"]


def test_try_is_read_only(monkeypatch):
    """The try must mount `:ro` and run `ls` only — never write/exec."""
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    seen = {}

    class _Proc:
        returncode = 0
        stdout = "total 0\ndrxr-x--- root root\n"
        stderr = ""

    def fake_run(argv, **kw):
        seen["argv"] = list(argv)
        return _Proc()

    monkeypatch.setattr(privesc_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(privesc_mod.shutil, "which", lambda _n: "/usr/bin/docker")
    out = privesc_mod.try_docker_group_read()
    assert out["success"] is True
    assert out["read_only"] is True
    assert "/:/host:ro" in seen["argv"]
    assert "ls" in seen["argv"]


def test_container_escape_detect_still_works():
    det = ContainerEscape().detect()
    assert "vectors" in det
    assert "capabilities" in det


def test_userns_report_shape():
    rep = privesc_mod.docker_group_report()
    assert "userns_available" in rep
    assert "userns_detail" in rep


def test_try_userns_uses_no_sudo_no_docker(monkeypatch):
    """The userns try must invoke only `unshare -Urm ...`, never sudo/docker."""
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    seen: list[list[str]] = []

    class _Proc:
        def __init__(self, stdout="", returncode=0):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode

    def fake_run(argv, **kw):
        seen.append(list(argv))
        if argv[:3] == ["/usr/bin/unshare", "-Urm", "id"]:
            return _Proc(stdout="uid=0(root) gid=0(root) groups=0(root)\n")
        return _Proc(
            stdout="ls: cannot open directory '/root': Permission denied", returncode=2
        )

    monkeypatch.setattr(privesc_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(privesc_mod.shutil, "which", lambda _n: "/usr/bin/unshare")
    out = privesc_mod.try_userns_root()
    assert out["success"] is True
    assert out["uses_sudo"] is False
    assert out["uses_docker"] is False
    assert out["host_root_still_denied"] is True
    assert all("sudo" not in a and "docker" not in a for argv in seen for a in argv)
    assert seen[0][:3] == ["/usr/bin/unshare", "-Urm", "id"]


def test_try_userns_disabled_in_sandbox(monkeypatch):
    monkeypatch.setenv("H4K_SANDBOX", "1")
    out = privesc_mod.try_userns_root()
    assert out["success"] is False
    assert "sandbox" in out["reason"]


@needs_hardened_host
def test_host_audit_uses_no_sudo_no_docker(monkeypatch):
    """Audit must never escalate and never touch docker.

    The audit may *execute* `sudo -n true` (no credentials, no privileged
    action — a gate check), but must never supply a password, run a
    container, or talk to the docker daemon.
    """
    seen: list[list[str]] = []
    real_run = privesc_mod.subprocess.run

    def fake_run(argv, **kw):
        seen.append(list(argv))
        return real_run(argv, **kw)

    monkeypatch.setattr(privesc_mod.subprocess, "run", fake_run)
    out = privesc_mod.host_privesc_audit()
    assert out["uses_sudo"] is False
    assert out["uses_docker"] is False
    # no privilege binary may be *used to escalate* (unit names like
    # docker.service appear as read-only query arguments to systemctl;
    # `sudo -n true` is allowed: no credentials, no privileged action).
    import os as _os

    for argv in seen:
        prog = _os.path.basename(argv[0]) if argv else ""
        assert prog not in ("su", "docker", "dockerd", "ctr", "runc")
        assert argv[0] != "/var/run/docker.sock"
        if prog == "sudo":
            # gate check (no creds, no priv action) or version string only
            assert argv[1:] in (["-n", "true"], ["--version"])
    for key in (
        "suid",
        "file_caps",
        "sensitive_writable",
        "verdict",
        "filecap_dac_bypass",
        "active_timers",
        "pkexec_version",
        "systemd_exec",
        "path_check",
        "polkit",
        "credential_gates",
    ):
        assert key in out
    # remaining vectors must be clean on this hardened host
    assert out["host_root_vector_found"] is False
    assert out["systemd_exec"]["writable_binaries"] == []
    assert out["systemd_exec"]["writable_units"] == []
    assert out["path_check"]["writable_path_dirs"] == []
    assert out["polkit"]["passwordless_vendor_rules"] == []
    assert out["credential_gates"]["credential_gate_holds"] is True
    assert out["uses_password"] is False
    assert out["cve_posture"]["chwoot"]["status"] == "patched"
    assert out["cve_posture"]["kernel_cve_hits"] == []


@needs_hardened_host
def test_credential_gates_prove_password_required():
    """sudo -n must fail and su trust must be off on this host."""
    gates = privesc_mod._credential_gates_check()
    assert gates["sudo_passwordless"] is False
    assert "password" in gates["sudo_detail"].lower()
    assert gates["su_wheel_trust"] is False
    assert gates["credential_gate_holds"] is True


def test_sudo_chwoot_status_parses_patch_levels():
    """Tuple comparison can't tell 1.9.17 from 1.9.17p2; this can."""
    assert (
        privesc_mod._sudo_chwoot_status("Sudo version 1.9.17p2")["status"] == "patched"
    )
    assert (
        privesc_mod._sudo_chwoot_status("Sudo version 1.9.17p1")["status"] == "patched"
    )
    assert (
        privesc_mod._sudo_chwoot_status("Sudo version 1.9.17")["status"] == "vulnerable"
    )
    assert (
        privesc_mod._sudo_chwoot_status("Sudo version 1.9.14")["status"] == "vulnerable"
    )
    assert privesc_mod._sudo_chwoot_status("garbage")["status"] == "unknown"


def test_kernel_copy_fail_range_flags_old_but_not_host():
    from services.version_detector import check_vulnerable_version

    assert check_vulnerable_version("linux", "6.18.21")[0]["cve"] == "CVE-2026-31431"
    assert check_vulnerable_version("linux", "7.2.8") == []
    assert check_vulnerable_version("linux", "6.19.12") == []


def test_zoneminder_second_order_sqli_range_matches_target():
    """1.36.35 (the .84 lab host) is in-window; the 1.36.38 fix is out."""
    from services.version_detector import check_vulnerable_version

    hits = check_vulnerable_version("zoneminder", "1.36.35")
    assert any(h["cve"] == "CVE-2026-27470" for h in hits)
    assert check_vulnerable_version("zoneminder", "1.36.38") == []


@needs_hardened_host
def test_filecap_probe_proves_no_dac_bypass():
    """Live probe: sys_admin file cap must not open root-only files."""
    bypassed, detail = privesc_mod._filecap_dac_probe()
    assert bypassed is False
    assert "Permission denied" in detail


@pytest.fixture()
def api_client(monkeypatch):
    """Real router, no daemon: the feature never touches MSF anyway."""
    from contextlib import asynccontextmanager

    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    import main as main_module

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    import main as mm

    mm._rate_store = None

    from fastapi.testclient import TestClient

    return TestClient(main_module.app)


@needs_hardened_host
def test_try_local_root_go_bro_shape(api_client):
    """The feature: one shot, all passwordless paths + audit, no password."""
    r = api_client.post("/api/tryLocalRoot_go_bro")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["feature"] == "tryLocalRoot_go_bro"
    assert body["uses_password"] is False
    assert body.get("verdict")
    for key in ("userns", "docker_group", "host_audit", "privilege"):
        assert key in body, key
    # userns try really ran here (no sudo, no docker involved)
    assert body["userns"]["success"] is True
    assert body["userns"]["uses_sudo"] is False
    assert body["userns"]["uses_docker"] is False
    # audit agrees with itself
    assert body["host_audit"]["host_root_vector_found"] is False
    assert body["host_root_achieved"] is False


def test_try_local_root_go_bro_disabled_tries_in_sandbox(api_client, monkeypatch):
    """Sandbox gates the tries but the endpoint still answers with the audit."""
    monkeypatch.setenv("H4K_SANDBOX", "1")
    r = api_client.post("/api/tryLocalRoot_go_bro")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["userns"]["success"] is False
    assert "sandbox" in body["userns"]["reason"]
    assert "host_audit" in body
