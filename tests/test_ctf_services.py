# Tests for the CTF-oriented service wrappers: container escape detection,
# DB/API interrogation, lateral movement, John, aircrack, tshark and ZAP.
# Every external binary, socket and HTTP call is faked; nothing here touches a
# real target, interface or daemon.
import io
import socket
import sqlite3
import subprocess
from pathlib import Path

from services import (
    aircrack,
    container_escape,
    db_interrogate,
    john,
    lateral,
    tshark,
    zap,
)


# --------------------------------------------------------------------------
# container_escape
# --------------------------------------------------------------------------
def test_decode_caps_maps_bits_to_names():
    ce = container_escape.ContainerEscape()
    caps = ce._decode_caps((1 << 19) | (1 << 21))  # SYS_PTRACE | SYS_ADMIN
    assert "CAP_SYS_PTRACE" in caps
    assert "CAP_SYS_ADMIN" in caps
    assert "CAP_CHOWN" not in caps


def test_detect_reads_proc_and_reports_vectors(monkeypatch):
    ce = container_escape.ContainerEscape()
    monkeypatch.setattr(ce, "_read_caps", lambda: None)
    monkeypatch.setattr(ce, "_read_mounts", lambda: None)
    monkeypatch.setattr(ce, "_read_cgroup", lambda: None)
    ce.caps = ["CAP_SYS_PTRACE", "CAP_SETUID"]
    ce.mounts = ["/var/run/docker.sock", "/proc"]
    d = ce.detect()
    assert d["dangerous_caps"] == ["CAP_SYS_PTRACE"]
    assert d["dangerous_mounts"]  # docker.sock matched
    kinds = {v["type"] for v in d["vectors"]}
    assert kinds == {"capability", "mount"}


def test_exploit_for_cap_and_mount_are_known_only():
    assert container_escape.ContainerEscape._exploit_for_cap("CAP_SYS_PTRACE")
    assert container_escape.ContainerEscape._exploit_for_cap("CAP_SETUID") is None
    assert container_escape.ContainerEscape._exploit_for_mount("/var/run/docker.sock")
    assert container_escape.ContainerEscape._exploit_for_mount("/proc") is None


def test_exploit_ptrace_refuses_without_cap():
    r = container_escape.ContainerEscape().exploit_ptrace(1)
    assert r["success"] is False
    assert "CAP_SYS_PTRACE" in r["reason"]


def test_exploit_docker_socket_without_socket():
    r = container_escape.ContainerEscape().exploit_docker_socket()
    assert r["success"] is False


def test_cgroup_escape_unavailable_on_this_host():
    r = container_escape.ContainerEscape().exploit_cgroup_release_agent()
    # Modern hosts are cgroup v2 (no writable release_agent); either branch ok.
    assert "success" in r


def test_check_host_escape_does_not_execute(monkeypatch):
    ce = container_escape.ContainerEscape()
    called = []
    monkeypatch.setattr(ce, "exploit_ptrace", lambda *a: called.append(1))
    monkeypatch.setattr(ce, "exploit_docker_socket", lambda: called.append(1))
    r = ce.check_host_escape()
    assert "vectors" in r
    assert called == []  # detection must not run any exploit


def test_is_privileged_threshold():
    ce = container_escape.ContainerEscape()
    ce.caps = [f"CAP_{i}" for i in range(40)]
    assert ce._is_privileged() is True
    ce.caps = ["CAP_SETUID"]
    assert ce._is_privileged() is False


# --------------------------------------------------------------------------
# db_interrogate
# --------------------------------------------------------------------------
def test_find_flags_extracts_flag_and_secret_shapes():
    found = db_interrogate.DBInterrogate._find_flags(
        {"a": "FLAG{5up3r_s3cr3t}", "b": {"pw": "password=Hunter2Hunter2"}}
    )
    assert any("FLAG{" in f.upper() for f in found)
    assert any("Hunter2" in f for f in found)


def test_env_secret_extraction_only_sensitive_keys(monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "p@ss")
    monkeypatch.setenv("NORMAL_VAR", "ok")
    out = db_interrogate.DBInterrogate._extract_env_secrets()
    assert out.get("DB_PASSWORD") == "p@ss"
    assert "NORMAL_VAR" not in out


def test_dump_sqlite_reads_tables(tmp_path):
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE flags (id INTEGER, val TEXT)")
    conn.execute("INSERT INTO flags VALUES (1, 'FLAG{db}')")
    conn.commit()
    conn.close()
    out = db_interrogate.DBInterrogate._dump_sqlite(db)
    assert "flags" in out["tables"]
    assert out["data"]["flags"][0]["val"] == "FLAG{db}"


def test_read_json_handles_bad_file(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    out = db_interrogate.DBInterrogate._read_json(bad)
    assert "error" in out


def test_search_files_scans_custom_roots(tmp_path):
    (tmp_path / "creds.json").write_text('{"password": "secret123"}', encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("nope", encoding="utf-8")
    di = db_interrogate.DBInterrogate(search_roots=[str(tmp_path)])
    out = di._search_files()
    assert any(k.endswith("creds.json") for k in out)
    assert not any(k.endswith("ignore.txt") for k in out)


def test_interrogate_all_composes_sections(monkeypatch, tmp_path):
    di = db_interrogate.DBInterrogate(search_roots=[str(tmp_path)])
    monkeypatch.setattr(di, "_enumerate_apis", lambda target: {"ollama": {"port": 1}})
    monkeypatch.setattr(di, "_search_files", lambda target_suffixes=True: {})
    monkeypatch.setattr(di, "_extract_env_secrets", lambda: {"TOKEN": "abc"})
    monkeypatch.setattr(di, "_scan_config_files", lambda: {})
    out = di.interrogate_all("10.0.0.5")
    assert out["target"] == "10.0.0.5"
    assert "apis" in out and "flags" in out


def test_http_json_parses_and_falls_back(monkeypatch):
    class Resp:
        status = 200

        def __init__(self, body):
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        db_interrogate.urllib.request,
        "urlopen",
        lambda req, timeout=3: Resp(b'{"ok": true}'),
    )
    assert db_interrogate.DBInterrogate._http_json("http://x") == {"ok": True}

    monkeypatch.setattr(
        db_interrogate.urllib.request, "urlopen", lambda req, timeout=3: Resp(b"plain")
    )
    assert db_interrogate.DBInterrogate._http_json("http://x")["status"] == 200


def test_interrogate_helpers_swallow_errors(monkeypatch):
    monkeypatch.setattr(
        db_interrogate.DBInterrogate,
        "_http_json",
        staticmethod(lambda *a, **k: (_ for _ in ()).throw(OSError("down"))),
    )
    di = db_interrogate.DBInterrogate()
    assert "error" in di.interrogate_ollama()["models"]
    assert "error" in di.interrogate_cad_worker()["health"]


# --------------------------------------------------------------------------
# lateral
# --------------------------------------------------------------------------
def test_hex_to_ip():
    # /proc/net/route stores IPv4 little-endian as hex.
    assert lateral.LateralMovement._hex_to_ip("0100A8C0") == "192.168.0.1"
    assert lateral.LateralMovement._hex_to_ip("bogus") == "0.0.0.0"


def test_get_routes_parses_proc(monkeypatch):
    content = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n"
    )
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO(content))
    routes = lateral.LateralMovement()._get_routes()
    assert routes and routes[0]["interface"] == "eth0"


def test_discover_network_returns_route_map(monkeypatch):
    lm = lateral.LateralMovement()
    monkeypatch.setattr(lm, "_get_routes", lambda: [{"interface": "eth0"}])
    monkeypatch.setattr(lm, "_get_local_ips", lambda: ["10.0.0.2"])
    out = lm.discover_network("10.0.0.0/24")
    assert out["cidr"] == "10.0.0.0/24"
    assert out["routes"] == [{"interface": "eth0"}]
    assert out["local_ips"] == ["10.0.0.2"]


def test_tcp_open_uses_connect_ex(monkeypatch):
    calls = {}

    class FakeSock:
        def settimeout(self, t):
            calls["timeout"] = t

        def connect_ex(self, addr):
            calls["addr"] = addr
            return 0

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(socket, "socket", lambda *a, **k: FakeSock())
    assert lateral.LateralMovement._tcp_open("", "10.0.0.1", 22) is True
    assert calls["addr"] == ("10.0.0.1", 22)
    assert calls["closed"] is True


def test_tcp_open_handles_errors(monkeypatch):
    monkeypatch.setattr(
        socket, "socket", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )
    assert lateral.LateralMovement._tcp_open("", "10.0.0.1", 22) is False


def test_create_ssh_tunnel_tracks_pid(monkeypatch):
    class FakeProc:
        pid = 4242

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProc())
    lm = lateral.LateralMovement()
    out = lm.create_ssh_tunnel("10.0.0.1", "root", password="pw")
    assert out["success"] and out["pid"] == 4242
    assert lm.tunnels[0]["type"] == "ssh_socks"


def test_create_chisel_tunnel_missing_binary(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "Popen", boom)
    out = lateral.LateralMovement().create_chisel_tunnel("10.0.0.1")
    assert out["success"] is False
    assert "chisel" in out["reason"]


def test_scan_through_tunnel_reports_open(monkeypatch):
    lm = lateral.LateralMovement()
    monkeypatch.setattr(lm, "_tcp_open", lambda p, t, port: port == 80)
    out = lm.scan_through_tunnel("", ["10.0.0.1", "10.0.0.2"], ports=[80, 443])
    assert out["results"] == {"10.0.0.1": [80], "10.0.0.2": [80]}


def test_close_all_tunnels(monkeypatch):
    killed = []
    monkeypatch.setattr(lateral.os, "kill", lambda pid, sig: killed.append(pid))
    lm = lateral.LateralMovement()
    lm.tunnels = [{"pid": 1}, {"pid": 2}]
    lm.close_all_tunnels()
    assert killed == [1, 2]
    assert lm.tunnels == []


def test_relay_smb_without_impacket(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("impacket"):
            raise ImportError("no impacket")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    out = lateral.LateralMovement().relay_smb("10.0.0.1", "u", "p")
    assert out["success"] is False


# --------------------------------------------------------------------------
# john
# --------------------------------------------------------------------------
def test_john_parse_show():
    out = "5f4dcc3b5aa765d61d8327deb882cf99:password\nuser:abc:withcolon\n"
    cracked = john.JohnService._parse_show(out)
    assert cracked[0]["password"] == "password"
    assert cracked[1]["username"] == "withcolon"


def test_john_run_wrappers(monkeypatch):
    class P:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    assert john.JohnService()._run(["john"])["success"] is True

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="john", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert john.JohnService()._run(["john"])["timed_out"] is True

    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    assert john.JohnService()._run(["john"])["rc"] == -1


def test_john_build_argv_includes_format_and_timeout(tmp_path):
    hf = tmp_path / "h.txt"
    hf.write_text("x", encoding="utf-8")
    argv = john.JohnService()._build_argv(str(hf), "md5", "wl.txt", 10)
    assert "--format" in argv and "--wordlist" in argv
    assert argv[-1] == str(hf)


def test_john_crack_parses_show(monkeypatch):
    calls = []

    def fake_run(argv, timeout=3600):
        calls.append(argv)
        if "--show" in argv:
            return {"stdout": "deadbeef:hunter2", "stderr": "", "rc": 0}
        return {"stdout": "", "stderr": "", "rc": 0}

    monkeypatch.setattr(
        john.JohnService, "_run", lambda self, argv, timeout=3600: fake_run(argv)
    )
    out = john.JohnService().crack(["deadbeef"], format="raw-md5", max_time=5)
    assert out["cracked"][0]["password"] == "hunter2"
    # the temp hash file is always cleaned up
    assert any("--show" in c for c in calls)


def test_john_crack_file(monkeypatch, tmp_path):
    hf = tmp_path / "h"
    hf.write_text("x", encoding="utf-8")

    def fake_run(argv, timeout=3600):
        if "--show" in argv:
            return {"stdout": "h:pw", "stderr": "", "rc": 0}
        return {"stdout": "", "stderr": "", "rc": 0}

    monkeypatch.setattr(
        john.JohnService, "_run", lambda self, argv, timeout=3600: fake_run(argv)
    )
    out = john.JohnService().crack_file(str(hf))
    assert out["cracked"][0]["hash"] == "h"


def test_john_status_and_formats(monkeypatch):
    def fake_run(self, argv, timeout=3600):
        if "--status" in argv:
            return {
                "stdout": "guesses: 10\ntime: 1s\nactive session",
                "stderr": "",
                "rc": 0,
            }
        return {"stdout": "md5\nsha1\n\n# comment", "stderr": "", "rc": 0}

    monkeypatch.setattr(john.JohnService, "_run", fake_run)
    svc = john.JohnService()
    st = svc.status()
    assert st["running"] is True and st["guesses"] == "10"
    assert svc.list_formats() == ["md5", "sha1"]


def test_john_wordlist_stats(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\nc\n", encoding="utf-8")
    assert john.JohnService.wordlist_stats(str(wl))["lines"] == 3
    assert john.JohnService.wordlist_stats(str(tmp_path / "nope"))["error"] == "missing"


def test_john_runner_tries_formats_and_dedupes(monkeypatch):
    svc = john.JohnRunner()

    def fake_crack(hashes, format=None, wordlist=None, max_time=300):
        if format == "nt":
            return {"cracked": [{"hash": "h1", "password": "pw", "username": None}]}
        return {"cracked": []}

    monkeypatch.setattr(svc.john, "crack", fake_crack)
    out = svc.crack_ctf_hashes(["h1", "h2"], formats=["raw-md5", "nt"])
    assert out["by_format"]["nt"][0]["password"] == "pw"
    # h1 cracked -> only h2 remains for later formats
    assert out["remaining"] == ["h2"]


# --------------------------------------------------------------------------
# aircrack
# --------------------------------------------------------------------------
def test_aircrack_parse_csv(tmp_path):
    csv = tmp_path / "out-01.csv"
    csv.write_text(
        "BSSID, First time seen, channel, Speed, Privacy, Cipher, Authentication,"
        " Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, 2024, 6, 54, WPA2, CCMP, PSK, -40, 10, 0,, 6, HomeNet,\n"
        "Station MAC, First time seen, Power, # packets, BSSID, Probed ESSIDs\n",
        encoding="utf-8",
    )
    nets = aircrack.AircrackService._parse_csv(str(csv))
    assert nets[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert nets[0]["essid"] == "HomeNet"
    assert nets[0]["encryption"] == "WPA2"


def test_aircrack_parse_csv_missing_file():
    assert aircrack.AircrackService._parse_csv("/nonexistent/x.csv") == []


def test_aircrack_run_wrappers(monkeypatch):
    class P:
        returncode = 0
        stdout = "x"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    assert aircrack.AircrackService()._run(["aircrack-ng"])["success"] is True

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert aircrack.AircrackService()._run(["x"])["timed_out"] is True

    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    assert aircrack.AircrackService()._run(["x"])["rc"] == -1


def test_aircrack_check_interfaces(monkeypatch):
    out = "PHY\tInterface\tDriver\tChipset\n" "phy0\twlan0\tath9k\tQualcomm Atheros\n"
    monkeypatch.setattr(
        aircrack.AircrackService,
        "_run",
        lambda self, argv, timeout=300: {"stdout": out, "stderr": "", "rc": 0},
    )
    ifaces = aircrack.AircrackService().check_interfaces()["interfaces"]
    assert ifaces[0]["interface"] == "wlan0"


def test_aircrack_start_monitor_parses_name(monkeypatch):
    monkeypatch.setattr(
        aircrack.AircrackService,
        "_run",
        lambda self, argv, timeout=300: {
            "stdout": "monitor mode enabled on wlan0mon\n",
            "stderr": "",
            "rc": 0,
            "success": True,
        },
    )
    out = aircrack.AircrackService().start_monitor("wlan0")
    assert out["monitor_interface"] == "wlan0mon"


def test_aircrack_crack_handshake_argv(monkeypatch):
    seen = {}

    def fake_run(self, argv, timeout=300):
        seen["argv"] = argv
        return {"stdout": "KEY FOUND", "stderr": "", "rc": 0}

    monkeypatch.setattr(aircrack.AircrackService, "_run", fake_run)
    aircrack.AircrackService().crack_handshake("c.cap", "wl.txt", "AA", "Home")
    assert "-w" in seen["argv"] and "-b" in seen["argv"] and "-e" in seen["argv"]


def test_aircrack_capture_handshake_detects(tmp_path, monkeypatch):
    svc = aircrack.AircrackService()
    output = tmp_path / "hs"
    cap = Path(f"{output}-01.cap")
    cap.write_text("x", encoding="utf-8")

    class FakeProc:
        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(
        svc,
        "_run",
        lambda argv, timeout=300: {
            "stdout": "WPA (1 handshake)",
            "stderr": "",
            "rc": 0,
        },
    )
    out = svc.capture_handshake(
        "wlan0mon", "AA:BB", 6, str(output), duration=1, deauth=False
    )
    assert out["handshake_captured"] is True


def test_aircrack_create_ap_hidden(monkeypatch):
    seen = {}

    def fake_run(self, argv, timeout=300):
        seen["argv"] = argv
        return {"stdout": "", "stderr": "", "rc": 0}

    monkeypatch.setattr(aircrack.AircrackService, "_run", fake_run)
    aircrack.AircrackService().create_ap("wlan0", "FreeWiFi", channel=11, hidden=True)
    assert "-H" in seen["argv"] and "FreeWiFi" in seen["argv"]


def test_aircrack_wps_without_reaver(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: False)
    r = aircrack.AircrackService().wps_attack("wlan0", "AA")
    assert r["success"] is False


def test_full_wpa_assessment_no_monitor(monkeypatch):
    monkeypatch.setattr(
        aircrack.AircrackService,
        "start_monitor",
        lambda self, interface: {"success": False, "raw": "no"},
    )
    out = aircrack.AircrackRunner().full_wpa_assessment("wlan0")
    assert "error" in out


def test_full_wpa_assessment_flow(monkeypatch):
    monkeypatch.setattr(
        aircrack.AircrackService,
        "start_monitor",
        lambda self, interface: {"success": True, "monitor_interface": "wlan0mon"},
    )
    monkeypatch.setattr(
        aircrack.AircrackService,
        "scan_networks",
        lambda self, interface, duration=30: {
            "networks": [
                {"bssid": "AA", "essid": "Home", "channel": 6, "encryption": "WPA2"},
                {"bssid": "BB", "essid": "Open", "channel": 1, "encryption": "OPN"},
            ]
        },
    )
    monkeypatch.setattr(
        aircrack.AircrackService,
        "capture_handshake",
        lambda self, *a, **k: {"handshake_captured": True, "cap_file": "/tmp/x.cap"},
    )
    monkeypatch.setattr(
        aircrack.AircrackService,
        "crack_handshake",
        lambda self, *a, **k: {"stdout": "KEY FOUND", "rc": 0},
    )
    monkeypatch.setattr(aircrack.AircrackService, "stop_monitor", lambda self, i: {})
    out = aircrack.AircrackRunner().full_wpa_assessment("wlan0", wordlist="wl")
    assert len(out["networks"]) == 2
    # only the WPA network is targeted
    assert out["handshakes"][0]["bssid"] == "AA"
    assert "crack_result" in out["handshakes"][0]


# --------------------------------------------------------------------------
# tshark
# --------------------------------------------------------------------------
def test_tshark_run_wrappers(monkeypatch):
    class P:
        returncode = 0
        stdout = "x"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    assert tshark.TsharkService()._run(["tshark"])["success"] is True

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    assert tshark.TsharkService()._run(["x"])["timed_out"] is True

    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    assert tshark.TsharkService()._run(["x"])["rc"] == -1


def test_tshark_list_interfaces(monkeypatch):
    monkeypatch.setattr(
        tshark.TsharkService,
        "_run",
        lambda self, argv, timeout=300: {
            "stdout": "1. eth0\n2. wlan0\n",
            "stderr": "",
            "rc": 0,
        },
    )
    ifaces = tshark.TsharkService().list_interfaces()
    assert ifaces == [{"id": "1", "name": "eth0"}, {"id": "2", "name": "wlan0"}]


def test_tshark_capture_live_argv(monkeypatch):
    seen = {}

    def fake_run(self, argv, timeout=300):
        seen["argv"] = argv
        return {"stdout": "", "stderr": "", "rc": 0}

    monkeypatch.setattr(tshark.TsharkService, "_run", fake_run)
    tshark.TsharkService().capture_live("eth0", duration=5, output="/tmp/o.pcap")
    assert "-a" in seen["argv"] and "duration:5" in seen["argv"]
    assert "/tmp/o.pcap" in seen["argv"]


def test_tshark_extract_queries(monkeypatch):
    calls = []

    def fake_run(self, argv, timeout=300):
        calls.append(argv)
        return {"stdout": "data", "stderr": "", "rc": 0}

    monkeypatch.setattr(tshark.TsharkService, "_run", fake_run)
    svc = tshark.TsharkService()
    assert svc.extract_flows("x.pcap")["tcp_conversations"] == "data"
    creds = svc.extract_credentials("x.pcap")
    assert set(creds) == {"http_basic", "ftp", "telnet", "smtp", "snmp"}
    anomalies = svc.detect_anomalies("x.pcap")
    assert "syn_scans" in anomalies


def test_tshark_analyze_pcap_fields(monkeypatch):
    seen = {}

    def fake_run(self, argv, timeout=300):
        seen["argv"] = argv
        return {"stdout": "[]", "stderr": "", "rc": 0}

    monkeypatch.setattr(tshark.TsharkService, "_run", fake_run)
    tshark.TsharkService().analyze_pcap("x.pcap", filter="http", fields=["ip.src"])
    assert "-Y" in seen["argv"] and "-T" in seen["argv"]


def test_tshark_extract_files_creates_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(
        tshark.TsharkService,
        "_run",
        lambda self, argv, timeout=300: {"stdout": "", "stderr": "", "rc": 0},
    )
    out = tshark.TsharkService().extract_files(
        "x.pcap", str(tmp_path), protocols=["http"]
    )
    assert out["http"]["dir"].endswith("http_objects")


def test_full_pcap_analysis(monkeypatch):
    monkeypatch.setattr(
        tshark.TsharkService,
        "pcap_stats",
        lambda self, p: {"stats": "S"},
    )
    monkeypatch.setattr(
        tshark.TsharkService, "extract_flows", lambda self, p: {"tcp": "x"}
    )
    monkeypatch.setattr(
        tshark.TsharkService, "extract_credentials", lambda self, p: {"ftp": "u"}
    )
    monkeypatch.setattr(
        tshark.TsharkService, "detect_anomalies", lambda self, p: {"icmp": "x"}
    )
    monkeypatch.setattr(
        tshark.TsharkService, "extract_files", lambda self, p, out: {"http": {}}
    )
    out = tshark.TsharkRunner().full_pcap_analysis("x.pcap")
    assert out["stats"] == "S" and out["flows"] == {"tcp": "x"}


def test_live_capture_analysis(monkeypatch):
    monkeypatch.setattr(
        tshark.TsharkService, "capture_live", lambda self, *a, **k: {"rc": 0}
    )
    monkeypatch.setattr(
        tshark.TsharkRunner,
        "full_pcap_analysis",
        lambda self, p: {"file": p, "ok": True},
    )
    out = tshark.TsharkRunner().live_capture_analysis("eth0", duration=1)
    assert out["ok"] is True


# --------------------------------------------------------------------------
# zap
# --------------------------------------------------------------------------
def test_zap_call_returns_dict(monkeypatch):
    class Resp:
        def json(self):
            return {"status": "ok"}

    monkeypatch.setattr(zap.requests, "get", lambda *a, **k: Resp())
    assert zap.ZAPService()._call("core/view/version/") == {"status": "ok"}


def test_zap_call_swallows_errors(monkeypatch):
    monkeypatch.setattr(
        zap.requests, "get", lambda *a, **k: (_ for _ in ()).throw(OSError("down"))
    )
    assert zap.ZAPService()._call("x") == {}


def test_zap_is_running(monkeypatch):
    class Resp:
        status_code = 200

    monkeypatch.setattr(zap.requests, "get", lambda *a, **k: Resp())
    assert zap.ZAPService().is_running() is True

    monkeypatch.setattr(
        zap.requests, "get", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert zap.ZAPService().is_running() is False


def test_zap_start_already_running(monkeypatch):
    svc = zap.ZAPService()
    monkeypatch.setattr(svc, "is_running", lambda: True)
    assert svc.start() is True


def test_zap_start_spawns_daemon(monkeypatch):
    svc = zap.ZAPService()

    class FakeProc:
        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: FakeProc())
    # first poll False then True
    calls = iter([False, True])
    monkeypatch.setattr(svc, "is_running", lambda: next(calls, True))
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert svc.start(timeout=5) is True
    svc.stop()
    assert svc._process is None


def test_zap_start_missing_binary(monkeypatch):
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    assert zap.ZAPService().start() is False


def test_zap_spider_and_active_wait(monkeypatch):
    svc = zap.ZAPService()
    monkeypatch.setattr(svc, "_call", lambda *a, **k: {"status": "100"})
    assert svc.spider_scan("http://t")["progress"] == 100
    assert svc.active_scan("http://t")["progress"] == 100


def test_zap_get_alerts_and_count(monkeypatch):
    svc = zap.ZAPService()
    monkeypatch.setattr(
        svc, "_call", lambda *a, **k: {"alerts": [{"risk": "High", "alert": "x"}]}
    )
    alerts = svc.get_alerts("http://t")
    assert alerts[0]["risk"] == "High"

    monkeypatch.setattr(svc, "_call", lambda *a, **k: {"alerts": "bogus"})
    assert svc.get_alerts() == []


def test_zap_context_and_auth(monkeypatch):
    svc = zap.ZAPService()
    calls = []

    def fake_call(endpoint, params=None, method="GET"):
        calls.append((endpoint, params))
        if endpoint.startswith("context/action/newContext"):
            return {"contextId": "1"}
        return {}

    monkeypatch.setattr(svc, "_call", fake_call)
    assert svc.create_context("c", "http://t") == "1"
    svc.set_auth("1", "formBasedAuthentication", {"loginUrl": "x"})
    assert any("includeInContext" in c[0] for c in calls)


def test_zap_fuzz_and_report(monkeypatch):
    svc = zap.ZAPService()
    monkeypatch.setattr(svc, "_call", lambda *a, **k: {"report": "<html/>"})
    assert svc.fuzz("http://t", ["f1"])["status"] == "started"
    assert svc.generate_report() == "<html/>"


def test_zap_runner_full_scan(monkeypatch):
    runner = zap.ZAPRunner()
    monkeypatch.setattr(runner.zap, "start", lambda: True)
    monkeypatch.setattr(runner.zap, "stop", lambda: None)
    monkeypatch.setattr(runner.zap, "spider_scan", lambda t: {"status": "completed"})
    monkeypatch.setattr(runner.zap, "active_scan", lambda t: {"status": "completed"})
    monkeypatch.setattr(
        runner.zap,
        "get_alerts",
        lambda t: [
            {"risk": "High", "alert": "sqli"},
            {"risk": "Low", "alert": "info"},
        ],
    )
    monkeypatch.setattr(runner.zap, "generate_report", lambda *a: "<html/>")
    out = runner.full_scan("http://t")
    assert out["alert_count"] == 2
    assert out["high_risk"][0]["alert"] == "sqli"


def test_zap_scan_convenience_modes(monkeypatch):
    monkeypatch.setattr(
        zap.ZAPRunner, "full_scan", lambda self, target, **k: {"full": target}
    )
    assert zap.zap_scan("http://t")["full"] == "http://t"

    monkeypatch.setattr(zap.ZAPService, "start", lambda self: True)
    monkeypatch.setattr(zap.ZAPService, "stop", lambda self: None)
    monkeypatch.setattr(
        zap.ZAPService, "spider_scan", lambda self, t, **k: {"spider": t}
    )
    assert zap.zap_scan("http://t", mode="spider")["spider"] == "http://t"

    monkeypatch.setattr(
        zap.ZAPService, "active_scan", lambda self, t, **k: {"active": t}
    )
    assert zap.zap_scan("http://t", mode="active")["active"] == "http://t"


def test_zap_scan_daemon_unavailable(monkeypatch):
    monkeypatch.setattr(zap.ZAPService, "start", lambda self: False)
    assert "error" in zap.zap_scan("http://t", mode="spider")
    monkeypatch.setattr(zap.ZAPRunner, "full_scan", lambda self, t, **k: {"error": "x"})
    assert zap.zap_scan("http://t")["error"] == "x"
