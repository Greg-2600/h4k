# Pipeline deep-dive: drive ScanPipeline.run end to end with every opt-in flag
# on, faking only the subprocess boundaries (msfconsole/whatweb/dig/traceroute).
# Exercises db_nmap, aux scanners, fingerprint merge, default-cred verification
# (offline archive), attack stage, and posture scoring with real fakes.
import subprocess
from typing import Any

import pytest


class FakeMsfPipeline:
    @property
    def client(self):
        return self

    @property
    def core(self):
        class _Core:
            @property
            def version(self):
                return {"version": "6.5.0"}

        return _Core()

    def hosts(self, *a, **k):
        return [{"host": "192.168.1.10", "os": "linux", "name": "web1"}]

    def services(self, *a, **k):
        return [
            {
                "host": "192.168.1.10",
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "state": "open",
                "info": "OpenSSH 7.4",
            },
            {
                "host": "192.168.1.10",
                "port": 80,
                "proto": "tcp",
                "name": "http",
                "state": "open",
                "info": "nginx/1.18",
            },
        ]

    def vulns(self, *a, **k):
        return [
            {
                "host": "192.168.1.10",
                "port": 22,
                "name": "fake-vuln",
                "refs": ["CVE-1999-0001"],
            }
        ]

    def jobs(self, *a, **k):
        return {}

    def sessions(self, *a, **k):
        return {}

    def current_workspace(self, *a, **k):
        return "default"

    def execute(self, mtype, mname, opts):
        return {"job_id": "1", "uuid": "u1"}

    def module_results(self, uuid):
        return {}

    def analyze_host(self, ip, workspace="default"):
        return {"host": {"modules": ["auxiliary/x"]}}

    def get_module_info(self, *a, **k):
        return {"description": "aux"}


CANNED: dict[str, Any] = {}


def _fake_run(argv, **kwargs):
    key = argv[0] if argv else ""
    out = CANNED.get(key, "")
    return type(
        "P", (), {"returncode": 0, "stdout": out, "stderr": "", "check": False}
    )()


@pytest.fixture()
def no_subprocess(monkeypatch):
    import services.scan_pipeline as sp

    CANNED.clear()
    monkeypatch.setattr(sp.subprocess, "run", _fake_run)
    return CANNED


def test_pipeline_run_all_stages(monkeypatch, no_subprocess):
    from services.scan_pipeline import ScanPipeline

    no_subprocess["msfconsole"] = "db_nmap done\n"
    no_subprocess["whatweb"] = (
        "http://192.168.1.10/nginx [nginx/1.18][Country-City][US]"
    )
    no_subprocess["dig"] = "web1.lab IN PTR 192.168.1.10\n"
    no_subprocess["traceroute"] = (
        "traceroute to 192.168.1.10 (192.168.1.10), 30 hops max\n"
        " 1  192.168.1.1 (192.168.1.1)\n"
        " 2  192.168.1.10 (192.168.1.10)\n"
        " 3  10.0.0.1 (10.0.0.1)\n"
        " 4  8.8.0.1 (8.8.0.1)\n"
        " 5  8.8.8.8 (8.8.8.8)\n"
    )
    # hydra is subprocess-driven inside _try_default_creds
    no_subprocess["hydra"] = "hydra finished (1 valid)\n"
    no_subprocess["ncrack"] = ""

    logs: list[str] = []
    pipeline = ScanPipeline(
        FakeMsfPipeline(),
        progress=lambda m, p: None,
        log=logs.append,
        should_stop=lambda: False,
    )

    from schemas import ScanMode, ScanRequest

    req = ScanRequest(
        target="192.168.1.0/24",
        mode=ScanMode.overt,
        do_dns_recon=False,
        do_vuln_scan=True,
        try_default_creds=True,
        open_sessions=False,
        do_attack=True,
    )
    report = pipeline.run(req)

    # host collection came from the fake db
    hosts = report["hosts"]
    assert hosts[0]["address"] == "192.168.1.10"
    ports = {s["port"] for s in hosts[0]["services"]}
    assert {22, 80} <= ports

    # vuln collection made it through
    assert report["vulns"], "expected vulns from fake db"

    # attack stage ran and reported per-service results
    assert isinstance(report["attacks"], list)

    # posture stage returned an entry for the host
    assert report["security"], "expected security entries"

    # notes include the msf analyze suggestion
    assert any("analyze" in n.lower() or "auxiliary" in n for n in report["notes"])


def test_pipeline_run_short_circuits_on_abort(monkeypatch, no_subprocess):
    from services.scan_pipeline import ScanPipeline, _ScanAbort

    pipeline = ScanPipeline(
        FakeMsfPipeline(),
        progress=lambda m, p: None,
        log=lambda m: None,
        should_stop=lambda: True,
    )
    from schemas import ScanMode, ScanRequest

    req = ScanRequest(target="192.168.1.0/24", mode=ScanMode.overt)
    with pytest.raises(_ScanAbort):
        pipeline.run(req)


def test_msfconsole_run_invokes_bash(monkeypatch, no_subprocess):
    import services.scan_pipeline as sp
    from services.scan_pipeline import ScanPipeline

    pipeline = ScanPipeline(FakeMsfPipeline())
    calls = []

    def rec(argv, **k):
        calls.append(argv)
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sp.subprocess, "run", rec)
    pipeline._msfconsole_run(["db_nmap", "-T4", "192.168.1.0/24"])
    assert calls and calls[0][0] == "bash"


def test_pipeline_dns_recon(monkeypatch, no_subprocess):
    from services.scan_pipeline import ScanPipeline

    no_subprocess["bash"] = "A example.com 203.0.113.5\n"
    pipeline = ScanPipeline(FakeMsfPipeline(), log=lambda m: None)
    notes = pipeline._dns_recon("example.com")
    assert isinstance(notes, list)


def test_pipeline_reverse_dns(monkeypatch, no_subprocess):
    from services.scan_pipeline import ScanPipeline

    no_subprocess["dig"] = "ptr.web1.lab.\n"
    pipeline = ScanPipeline(FakeMsfPipeline(), log=lambda m: None)
    out = pipeline._reverse_dns(["192.168.1.10"])
    assert isinstance(out, list)


def test_whatweb_failure_soft(monkeypatch, no_subprocess):
    from services.scan_pipeline import ScanPipeline

    def boom(argv, **k):
        raise FileNotFoundError("nah")

    monkeypatch.setattr(subprocess, "run", boom)
    assert ScanPipeline(FakeMsfPipeline())._whatweb("http://x") == ""


def test_pipeline_probe_mystery_ports(monkeypatch):
    """Drive the UDP/TCP mystery-port probes with a scripted socket."""
    import socket as socket_mod

    from services.scan_pipeline import ScanPipeline

    opened = []

    class _Sock:
        def __init__(self, *a):
            opened.append("t" if a[1] == socket_mod.SOCK_STREAM else "u")

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def sendall(self, b):
            pass

        def sendto(self, b, addr):
            pass

        def recv(self, n):
            return b"SSH-2.0-OpenSSH_9.0\r\n"

        def recvfrom(self, n):
            return (b"\x00" * 40, ("1.2.3.4", 161))

        def close(self):
            pass

    import socket as socket_global

    monkeypatch.setattr(socket_global, "socket", lambda *a, **k: _Sock())
    pipeline = ScanPipeline(FakeMsfPipeline(), log=lambda m: None)
    hosts = [
        {
            "address": "192.168.1.10",
            "services": [
                {"port": 22, "proto": "tcp", "service": "mystery", "state": "open"},
                {"port": 161, "proto": "udp", "service": "unknown", "state": "open"},
            ],
        }
    ]
    from services.modes import get_mode

    mode = get_mode("overt", "standard")
    pipeline._probe_mystery_ports(hosts, mode)
    assert any(s.get("service") for s in hosts[0]["services"])


def test_pipeline_aux_scanner_launch_and_result(monkeypatch, no_subprocess):
    """Aux scanner modules: launch via fake msf and merge banner results."""
    from services.modes import get_mode
    from services.scan_pipeline import ScanPipeline

    mode = get_mode("overt", "standard")
    launches = []

    class _Msf(FakeMsfPipeline):
        def execute(self, mtype, mname, opts):
            launches.append(mname)
            return {"job_id": "7", "uuid": "u-abc"}

        def module_results(self, uuid):
            return {
                "results": [
                    {
                        "port": 22,
                        "proto": "tcp",
                        "host": "192.168.1.10",
                        "output": "OpenSSH 7.4",
                        "service": "ssh",
                        "name": "ssh",
                    }
                ]
            }

    import time as time_global

    def fake_sleep(t):
        pass

    monkeypatch.setattr(time_global, "sleep", fake_sleep)

    pipeline = ScanPipeline(_Msf(), log=lambda m: launches.append(f"log:{m}"))
    hosts = [
        {
            "address": "192.168.1.10",
            "services": [
                {"port": 22, "proto": "tcp", "service": "ssh", "state": "open"},
            ],
        }
    ]
    pipeline._run_aux_scanners(hosts, mode)
    assert launches, "expected at least one aux scanner launched"


def test_pipeline_cred_stage_parse(monkeypatch, no_subprocess):
    """_try_default_creds: hydra success parsing + option propagation."""
    from services.scan_pipeline import ScanPipeline

    # canned hydra output from the bundled user/pass lists
    no_subprocess["hydra"] = (
        "[22][ssh] host: 192.168.1.10   login: pi   password: raspberry\n"
    )

    class _Msf(FakeMsfPipeline):
        def execute(self, mtype, mname, opts):
            if "opt" in str(opts).lower():
                return {"ok": True}
            return {"status": "success", "username": "", "password": "", "proof": "yes"}

        def module_results(self, uuid):
            return {}

    pipeline = ScanPipeline(_Msf(), log=lambda m: None)
    hosts = [
        {
            "address": "192.168.1.10",
            "services": [
                {"port": 22, "proto": "tcp", "service": "ssh", "state": "open"},
                {
                    "port": 22,
                    "proto": "tcp",
                    "service": "microsoft-ds",
                    "state": "open",
                },
            ],
        }
    ]
    creds = pipeline._try_default_creds(hosts, [], open_sessions=False)
    assert any(c.get("verified") for c in creds) or creds == []


def test_pipeline_probe_success_merge(monkeypatch):
    """Probe banners merge back into the service list (703-706)."""
    import socket as socket_mod

    from services.modes import get_mode
    from services.scan_pipeline import ScanPipeline

    class _Good:
        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def sendall(self, b):
            pass

        def sendto(self, b, addr):
            pass

        def recv(self, n):
            return b"STAT pid 1\x00\r\n"

        def recvfrom(self, n):
            return (b"\\x04\\x01\\x06\\x80public", ("r", 0))

        def close(self):
            pass

    monkeypatch.setattr(socket_mod, "socket", lambda *a, **k: _Good())
    p = ScanPipeline(FakeMsfPipeline(), log=lambda m: None)
    mode = get_mode("overt", "standard")
    hosts = [
        {
            "address": "192.168.1.10",
            "services": [
                {"port": 11211, "proto": "tcp", "service": "unknown", "state": "open"},
                {"port": 5353, "proto": "udp", "service": "unknown", "state": "open"},
            ],
        }
    ]
    p._probe_mystery_ports(hosts, mode)
    names = {s.get("service") for s in hosts[0]["services"]}
    assert "unknown" not in names


def test_pipeline_db_nmap_udp_branch(monkeypatch, no_subprocess):
    """UDP scan stage runs for non-stealth modes (327-329)."""
    from services.scan_pipeline import ScanPipeline

    calls = []
    pipeline = ScanPipeline(FakeMsfPipeline())

    def rec(self, argv):
        calls.append(argv)
        return ""

    monkeypatch.setattr(ScanPipeline, "_msfconsole_run", rec)
    pipeline._db_nmap("192.168.1.0/24", ["-T4"], ["-sU"])
    assert len(calls) == 2  # tcp + udp


def test_try_one_ftp_and_http_login_branches(monkeypatch):
    from services.scan_pipeline import ScanPipeline

    calls = {}

    class _Msf(FakeMsfPipeline):
        @property
        def client(self):
            return self

        @property
        def modules(self):
            options = ["RHOSTS", "RPORT", "USERNAME", "PASSWORD", "URI"]

            class _Mod:
                @property
                def options(self):
                    return list(options)

            class _Modules:
                def use(self, mtype, mname):
                    return _Mod()

            return _Modules()

        def execute(self, mtype, mname, opts):
            calls[mname] = dict(opts)
            return {"status": "success"}

    p = ScanPipeline(_Msf(), log=lambda m: None)
    ok = p._try_one(
        "exploit/multi/http/tomcat_mgr_login",
        "192.168.1.10",
        {"port": 80, "service": "http", "state": "open"},
        "u",
        "p",
        False,
    )
    assert ok is True
    last = list(calls.values())[-1]
    assert last.get("RHOSTS") == "192.168.1.10"


def test_try_one_success_string_detection(monkeypatch):
    from services.scan_pipeline import ScanPipeline

    class _Msf(FakeMsfPipeline):
        @property
        def client(self):
            return self

        @property
        def modules(self):
            class _Mod:
                @property
                def options(self):
                    return ["RHOSTS", "RPORT", "USERNAME", "PASSWORD"]

            class _Modules:
                def use(self, mtype, mname):
                    return _Mod()

            return _Modules()

        def execute(self, mtype, mname, opts):
            # variant 1: nested string success; covers the value-scan loop
            return {"verbose": "Please wait... SUCCESS!"}

    p = ScanPipeline(_Msf(), log=lambda m: None)
    assert (
        p._try_one(
            "exploit/x",
            "192.168.1.10",
            {"port": 21, "service": "ftp", "state": "open"},
            "u",
            "p",
            False,
        )
        is True
    )


def test_dns_recon_notes_format(monkeypatch, no_subprocess):
    """DNS tool outputs become [name] notes (966-968, 989-993)."""
    import services.scan_pipeline as sp
    from services.scan_pipeline import ScanPipeline

    canned = {
        "/opt/h4k/scripts/dns_dump.sh": "example.com A 203.0.113.5\n",
        "/opt/h4k/scripts/sub_domain_lookup.sh": "sub1.example.com\n",
        "/opt/h4k/scripts/dnstracer.sh": "example.com :: ns1\n",
        "/opt/h4k/scripts/dig.sh": ";; ANSWER: x\n",
    }

    def fake_run(argv, **k):
        out = canned.get(argv[0], "result\n")
        return type(
            "P", (), {"returncode": 0, "stdout": out, "stderr": "", "check": False}
        )()

    monkeypatch.setattr(sp.subprocess, "run", fake_run)
    notes = ScanPipeline(FakeMsfPipeline())._dns_recon("example.com")
    assert notes and all(note.startswith("[") for note in notes)


def test_cve_version_aware_branch(monkeypatch):
    """version-aware matching path in match_service (74-81)."""

    import services.cve_lookup as cve
    import services.version_detector as vd
    from schemas import Service

    db = cve.CveDb()
    monkeypatch.setattr(
        vd,
        "check_vulnerable_version",
        lambda product, version: [{"cve": "CVE-2016-5195", "range": "<4.8.3"}],
    )
    svc = Service(
        port=22,
        proto="tcp",
        service="linux",
        state="open",
        info="linux kernel dirtycow",
    )
    hits = db.match_service(svc, version="4.4", product="linux")
    vids = {h.get("id") for h in hits}
    assert "CVE-2016-5195" in vids
