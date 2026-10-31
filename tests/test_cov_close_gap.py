# Gap-closer: unit coverage for auth / ad_tools / ai / privesc edges /
# container_escape exploits / auto_scan helpers. All offline with fakes.
import subprocess as _sp


def test_auth_edges(monkeypatch):
    import services.auth as auth

    assert auth.is_exempt("") is False
    assert auth.is_exempt("/") is True
    assert auth.is_exempt("/api/health") is True
    assert auth.is_exempt("/static/x") is True
    assert auth.is_exempt("/docs/") is True
    assert auth.is_exempt("/redoc/") is True
    assert auth.is_exempt("/api/scan") is False

    monkeypatch.delenv("H4K_API_KEY", raising=False)
    assert auth.api_key() is None
    assert auth.auth_enabled() is False
    assert auth.check_key(None) is True  # disabled -> open
    assert auth.check_key("anything") is True

    monkeypatch.setenv("H4K_API_KEY", "  k1  ")
    assert auth.api_key() == "k1"
    assert auth.auth_enabled() is True
    assert auth.check_key(None) is False
    assert auth.check_key("") is False
    assert auth.check_key("wrong") is False
    assert auth.check_key("k1") is True


def test_ad_tools_run_edges(monkeypatch):
    import services.ad_tools as ad

    svc = ad.ADToolsService()

    class _P:
        def __init__(self, rc=0, out="", err=""):
            self.returncode = rc
            self.stdout = out
            self.stderr = err

    # timeout path
    def _boom_timeout(*a, **k):
        raise _sp.TimeoutExpired(cmd="x", timeout=1, output=b"partial", stderr=None)

    monkeypatch.setattr(ad.subprocess, "run", _boom_timeout)
    out = svc._run(["x"])
    assert out["timed_out"] is True
    assert out["stdout"] == "partial"

    # FileNotFound path
    def _boom_missing(*a, **k):
        raise FileNotFoundError("nope")

    monkeypatch.setattr(ad.subprocess, "run", _boom_missing)
    out = svc._run(["x"])
    assert out["rc"] == -1 and "not installed" in out["stderr"]

    # generic exception path
    def _boom_other(*a, **k):
        raise RuntimeError("weird")

    monkeypatch.setattr(ad.subprocess, "run", _boom_other)
    out = svc._run(["x"])
    assert out["rc"] == -1

    # success path with all argv options
    monkeypatch.setattr(ad.subprocess, "run", lambda *a, **k: _P(0, "ok", ""))
    assert (
        svc.bloodhound_collect(
            "LAB", "u", "p", dc_ip="1.2.3.4", output_dir="/tmp/x", zip_output=False
        )["success"]
        is True
    )
    assert (
        svc.mitm6_attack("eth0", domain="lab", ipv4="10.0.0.1", config_file="/tmp/c")[
            "success"
        ]
        is True
    )
    assert (
        svc.responder_attack(
            "eth0",
            analyze_mode=True,
            fingerprint=True,
            http_port=8080,
            https_port=8443,
            smb_port=445,
        )["success"]
        is True
    )

    # relay chain: mitm6 fails -> no bloodhound key
    monkeypatch.setattr(
        ad.ADToolsService, "mitm6_attack", lambda self, *a, **k: {"success": False}
    )
    res = svc.relay_chain("eth0", "LAB", "1.2.3.4", "u", "p")
    assert "mitm6" in res and "bloodhound" not in res
    # relay chain: mitm6 succeeds -> bloodhound collected
    monkeypatch.setattr(
        ad.ADToolsService, "mitm6_attack", lambda self, *a, **k: {"success": True}
    )
    monkeypatch.setattr(
        ad.ADToolsService,
        "bloodhound_collect",
        lambda self, *a, **k: {"success": True},
    )
    res = svc.relay_chain("eth0", "LAB", "1.2.3.4", "u", "p")
    assert "bloodhound" in res

    # _as_text variants + module-level wrappers
    assert ad._as_text(None) == ""
    assert ad._as_text(b"ab") == "ab"
    assert ad._as_text("s") == "s"
    assert isinstance(ad.bloodhound_collect("L", "u", "p"), dict)
    assert isinstance(ad.mitm6_attack("eth0"), dict)
    assert isinstance(ad.responder_attack("eth0"), dict)


def test_ai_unit_edges(monkeypatch):
    import services.ai as ai

    monkeypatch.setenv("H4K_AI_PROVIDER", "OLLAMA")
    assert ai._provider() == "ollama"
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://x:11434/")
    assert ai._olla_base() == "http://x:11434"
    assert ai._chat_endpoint().endswith("/api/chat")
    monkeypatch.delenv("H4K_AI_MODEL", raising=False)
    assert ai._model() == ai.DEFAULT_MODEL
    monkeypatch.setenv("H4K_AI_MODEL", "mymodel")
    assert ai._model() == "mymodel"

    class _Resp:
        def __init__(self, payload: bytes):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._payload

    # probe ok
    monkeypatch.setattr(
        ai.urllib.request,
        "urlopen",
        lambda req, timeout=5: _Resp(b'{"models": []}'),
    )
    assert ai._probe_ollama() is True

    # probe raises -> False
    def _boom(req, timeout=5):
        raise OSError("down")

    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    assert ai._probe_ollama() is False
    assert ai.ollama_models() == []

    # models list success
    monkeypatch.setattr(
        ai.urllib.request,
        "urlopen",
        lambda req, timeout=5: _Resp(b'{"models": [{"name": "qwen2.5:latest"}, {}]}'),
    )
    assert ai.ollama_models() == ["qwen2.5:latest"]

    # ensure: already present
    monkeypatch.setattr(
        ai.urllib.request,
        "urlopen",
        lambda req, timeout=10: _Resp(b'{"models": [{"name": "mymodel:latest"}]}'),
    )
    assert ai._ensure_ollama_model("mymodel") is True
    # ensure: list fails -> False
    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    assert ai._ensure_ollama_model("mymodel") is False
    # ensure: pull succeeds
    calls = {"n": 0}

    def _pull(req, timeout=600):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp(b'{"models": []}')
        return _Resp(b"{}")

    monkeypatch.setattr(ai.urllib.request, "urlopen", _pull)
    assert ai._ensure_ollama_model("newmodel") is True

    # ai_analyze: ollama unreachable
    monkeypatch.setenv("H4K_AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai, "_probe_ollama", lambda: False)
    out = ai.ai_analyze("hi")
    assert out["ok"] is False and out["provider"] == "ollama"

    # ai_analyze: ollama success
    monkeypatch.setattr(ai, "_probe_ollama", lambda: True)
    monkeypatch.setattr(ai, "_ensure_ollama_model", lambda m: True)
    monkeypatch.setattr(
        ai.urllib.request,
        "urlopen",
        lambda req, timeout=180: _Resp(b'{"message": {"content": "ROOT_CAUSE: x"}}'),
    )
    out = ai.ai_analyze("hi")
    assert out["ok"] is True and "ROOT_CAUSE" in out["raw"]

    # ai_analyze: ollama raises softly
    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    out = ai.ai_analyze("hi")
    assert out["ok"] is False and out["raw"] == ""

    # _call_openai without key -> auth header absent but still posts
    monkeypatch.delenv("H4K_AI_KEY", raising=False)
    monkeypatch.setattr(
        ai.urllib.request,
        "urlopen",
        lambda req, timeout=120: _Resp(
            b'{"choices": [{"message": {"content": "ROOT_CAUSE: y"}}]}'
        ),
    )
    out = ai._call_openai("hi", "m")
    assert out["ok"] is True
    monkeypatch.setenv("H4K_AI_KEY", "k")
    out = ai._call_openai("hi", "m")
    assert out["ok"] is True
    monkeypatch.setattr(ai.urllib.request, "urlopen", _boom)
    out = ai._call_openai("hi", "m")
    assert out["ok"] is False


def test_privesc_edge_branches(monkeypatch):
    import services.privesc as pz

    # every `which` miss path
    monkeypatch.setattr(pz.shutil, "which", lambda _n: None)
    assert pz._filecap_dac_probe()[0] is False
    assert "not installed" in pz._sudo_version()
    assert "not installed" in pz._pkexec_version()
    assert pz._active_timers() == []
    assert pz._systemd_exec_audit()["checked"] == 0
    assert pz._userns_available()[0] is False
    assert pz._docker_works()[0] is False
    assert pz.try_docker_group_read()["success"] is False
    assert pz.try_userns_root()["success"] is False

    # subprocess exception paths
    def _boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(pz.shutil, "which", lambda _n: "/usr/bin/x")
    monkeypatch.setattr(pz.subprocess, "run", _boom)
    assert pz._filecap_dac_probe()[1].startswith("probe failed")
    assert "unknown" in pz._sudo_version()
    assert "unknown" in pz._pkexec_version()
    assert pz._active_timers() == []
    assert pz._systemd_exec_audit()["checked"] == 0
    assert "failed" in pz._userns_available()[1]
    assert "failed" in pz._docker_works()[1]
    assert pz.try_docker_group_read()["success"] is False
    assert pz.try_userns_root()["success"] is False

    # filecap outputs
    class _P:
        def __init__(self, out="", err="", rc=0):
            self.stdout = out
            self.stderr = err
            self.returncode = rc

    monkeypatch.setattr(
        pz.subprocess, "run", lambda *a, **k: _P("Permission denied", "", 0)
    )
    ok, detail = pz._filecap_dac_probe()
    assert ok is False and "Permission denied" in detail

    # sudo --version empty output
    monkeypatch.setattr(pz.subprocess, "run", lambda *a, **k: _P("", "", 0))
    assert pz._sudo_version() == "unknown"

    # systemd audit with units but show fails
    def _fake_systemd(argv, **kw):
        if "list-units" in argv:
            return _P("cron.service loaded active\n", "", 0)
        raise OSError("show failed")

    monkeypatch.setattr(pz.subprocess, "run", _fake_systemd)
    assert pz._systemd_exec_audit()["checked"] == 0

    # credential gates: no sudo binary
    monkeypatch.setattr(pz.shutil, "which", lambda _n: None)
    gates = pz._credential_gates_check()
    assert "not installed" in gates["sudo_detail"]

    # 32462-only branch (1.9.5, pre-chroot bug but in host-option window)
    assert (
        pz._sudo_chwoot_status("Sudo version 1.9.5")["status"]
        == "vulnerable-32462-only"
    )

    # docker groups: no group entry
    import grp as _grp

    monkeypatch.setattr(_grp, "getgrnam", lambda _n: (_ for _ in ()).throw(KeyError()))
    assert pz._docker_groups() == []

    # docker groups: OSError on getgroups
    import os as _os

    class _Ent:
        gr_gid = 999

    monkeypatch.setattr(_grp, "getgrnam", lambda _n: _Ent())
    monkeypatch.setattr(_os, "getgroups", lambda: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(pz, "_euid", lambda: 0)
    assert pz._docker_groups() == ["docker"]

    # in-container via dockerenv
    monkeypatch.setattr(pz.Path, "exists", lambda self: True)
    assert pz._in_container() is True

    # direct root read: already root / missing / generic
    monkeypatch.setattr(pz.Path, "iterdir", lambda self: iter([pz.Path("/")]))
    assert pz._direct_root_read()[0] is True

    # report vector branches: socket-in-container, euid 0, userns
    monkeypatch.setattr(pz, "_euid", lambda: 0)
    monkeypatch.setattr(pz, "_in_container", lambda: True)
    monkeypatch.setattr(pz, "_docker_groups", lambda: [])
    monkeypatch.setattr(pz, "_docker_works", lambda timeout=5.0: (False, "no"))
    monkeypatch.setattr(pz, "_direct_root_read", lambda: (False, "denied"))
    monkeypatch.setattr(pz.Path, "exists", lambda self: True)
    monkeypatch.setattr(pz, "_userns_available", lambda timeout=5.0: (True, "ns"))
    rep = pz.docker_group_report()
    types = {v["type"] for v in rep["vectors"]}
    assert {"mount", "identity", "userns"} <= types

    # try_docker: image fallback + failing rc
    monkeypatch.delenv("H4K_SANDBOX", raising=False)
    monkeypatch.setattr(pz.shutil, "which", lambda _n: "/usr/bin/docker")
    monkeypatch.setattr(pz, "_direct_root_read", lambda: (False, "denied"))
    monkeypatch.setattr(
        pz.subprocess,
        "run",
        lambda argv, **kw: _P("", "", 0) if "images" in argv else _P("total 0", "", 1),
    )
    out = pz.try_docker_group_read()
    assert out["image"] == "alpine:3.20"
    assert out["success"] is False

    # try_userns: host check raises -> None
    def _fake_unshare(argv, **kw):
        if argv[-1] == "id":
            return _P("uid=0(root)", "", 0)
        raise OSError("ls failed")

    monkeypatch.setattr(pz.subprocess, "run", _fake_unshare)
    out = pz.try_userns_root()
    assert out["success"] is True
    assert out["host_root_still_denied"] is None


def test_container_escape_edges(monkeypatch):
    from services.container_escape import ContainerEscape

    ce = ContainerEscape()
    # no cap -> ptrace refuses without touching ctypes
    ce.caps = []
    assert ce.exploit_ptrace(1)["success"] is False
    # no docker SDK
    import importlib.util as _ilu

    monkeypatch.setattr(_ilu, "find_spec", lambda _n: None)
    assert ce.exploit_docker_socket()["success"] is False
    # no release agent
    assert ce.exploit_cgroup_release_agent()["success"] is False
    # helpers
    assert ce._is_privileged() is False
    assert ContainerEscape._exploit_for_cap("CAP_SYS_PTRACE") is not None
    assert ContainerEscape._exploit_for_cap("CAP_SYS_TIME") is None
    assert ContainerEscape._exploit_for_mount("/var/run/docker.sock") is not None
    assert ContainerEscape._exploit_for_mount("/nope") is None
    assert ContainerEscape().check_host_escape()["vectors"] == []

    # generate vectors from dangerous caps + mounts
    ce2 = ContainerEscape()
    ce2.caps = ["CAP_SYS_PTRACE", "CAP_CHOWN"]
    ce2.mounts = ["/var/run/docker.sock", "/data"]
    vecs = ce2._generate_vectors()
    assert any(v["name"] == "CAP_SYS_PTRACE" for v in vecs)
    assert any(v["name"] == "/var/run/docker.sock" for v in vecs)
    ce2.caps = ["CAP_CHOWN"] * 40
    assert ce2._is_privileged() is True


def test_auto_scan_edges(monkeypatch, tmp_path):
    import services.auto_scan as asc

    monkeypatch.setenv("H4K_AUTO_SCAN", "0")
    assert asc.enabled() is False
    monkeypatch.setenv("H4K_AUTO_SCAN", "1")
    assert asc.enabled() is True

    monkeypatch.setenv("H4K_AUTO_SCAN_CIDR", "10.9.0.0/24")
    assert asc.detect_local_cidr() == "10.9.0.0/24"
    monkeypatch.delenv("H4K_AUTO_SCAN_CIDR", raising=False)

    class _P:
        returncode = 0
        stdout = "default via 10.1.1.1 dev eth0 src 10.1.2.3"

    monkeypatch.setattr(asc.subprocess, "run", lambda *a, **k: _P())
    assert asc.detect_local_cidr() == "10.1.2.0/24"

    def _boom(*a, **k):
        raise OSError("no ip")

    monkeypatch.setattr(asc.subprocess, "run", _boom)
    assert asc.detect_local_cidr() == "192.168.1.0/24"

    # engagement store unavailable
    monkeypatch.setattr(
        "services.engagement.EngagementStore",
        lambda *a, **k: (_ for _ in ()).throw(OSError("db down")),
    )
    assert asc._ensure_engagement("10.0.0.0/24") is None

    # start respects disabled; stop/status round-trip
    monkeypatch.setenv("H4K_AUTO_SCAN", "0")
    asc._state["running"] = False
    asc.start()
    assert asc.status()["last_status"] == "disabled"
    asc._state["running"] = True
    asc.start()  # already running -> no-op
    asc.stop()
    assert asc.status()["running"] is False

    # one pass with faked discovery/toolkit/cve/store
    import services.auto_scan as asc2

    class _N:
        def __init__(self, ip):
            self.ip = ip
            self.mac = "aa:bb"
            self.hostname = "h"

    class _Finder:
        def __init__(self, msf):
            pass

        def discover(self, cidr):
            return [_N("10.0.0.5")]

    class _Runner:
        def __init__(self, progress=None):
            pass

        def run_tool(self, tool, argv, timeout=15):
            return {"status": "ok", "stdout": "<host></host>"}

    monkeypatch.setattr("services.discovery.NeighborFinder", _Finder)
    monkeypatch.setattr("services.toolkit.ToolkitRunner", _Runner)
    monkeypatch.setattr(
        "routers.scan._parse_nmap_xml",
        lambda xml: [
            {
                "ip": "10.0.0.5",
                "services": [
                    {
                        "port": 22,
                        "state": "open",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "9.0",
                    }
                ],
                "os": None,
            }
        ],
    )
    monkeypatch.setattr(
        "routers.scan._match_service_vulns",
        lambda ip, svc: [{"vid": "CVE-2024-1", "severity": "high", "detail": "d"}],
    )

    class _Store:
        def get_engagement(self, eid):
            return None

        def ingest_scan(self, eid, report):
            raise AssertionError("should not ingest when missing")

    monkeypatch.setattr("services.engagement.EngagementStore", lambda: _Store())
    summary = asc2._run_one_pass("10.0.0.0/24", "eng-1")
    assert summary["hosts"] == 1
    assert summary["vulns"] == 1
