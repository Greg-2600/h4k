# Tests for the local TLS lab. All filesystem work is redirected into tmp_path
# via the module-level path constants, and openssl/socat are faked, so these
# tests never touch the real system trust store or spawn a proxy.
import subprocess
from pathlib import Path

import pytest
from services import tls_lab


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Point every tls_lab path constant at a tmp dir."""
    d = tmp_path / "tls-lab"
    monkeypatch.setattr(tls_lab, "LAB_DIR", d)
    monkeypatch.setattr(tls_lab, "CA_KEY", d / "ca.key")
    monkeypatch.setattr(tls_lab, "CA_CRT", d / "ca.crt")
    monkeypatch.setattr(tls_lab, "SERV_KEY", d / "server.key")
    monkeypatch.setattr(tls_lab, "SERV_CRT", d / "server.crt")
    monkeypatch.setattr(tls_lab, "SERV_CSR", d / "server.csr")
    monkeypatch.setattr(tls_lab, "SERV_CNF", d / "server.ext")
    monkeypatch.setattr(tls_lab, "CERT_BUNDLE", d / "server.pem")
    return d


def _pretend_openssl_ok(monkeypatch, calls):
    """Fake _which(_run) that makes every openssl step 'succeed' and touch the
    output file the step would normally create."""
    monkeypatch.setattr(tls_lab, "_which", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: False)

    def run(cmd, timeout=60):
        calls.append(cmd)
        if "-out" in cmd:
            Path(cmd[cmd.index("-out") + 1]).write_text("x", encoding="utf-8")
        return 0

    monkeypatch.setattr(tls_lab, "_run", run)
    return calls


def test_setup_requires_openssl(lab, monkeypatch):
    monkeypatch.setattr(tls_lab, "_which", lambda t: None)
    r = tls_lab.setup_ca()
    assert r["ok"] is False
    assert "openssl not installed" in r["error"]


def test_setup_creates_ca_and_server_cert(lab, monkeypatch):
    calls = _pretend_openssl_ok(monkeypatch, [])
    r = tls_lab.setup_ca()
    # on success setup_ca returns a status() dict (no "ok" key)
    assert r.get("ok", True) is True
    assert lab.is_dir()
    # CA key, self-signed CA, server key, CSR, and the signing step all ran
    joined = [" ".join(c) for c in calls]
    assert any("genrsa" in c and "ca.key" in c for c in joined)
    assert any("req -x509" in c and "ca.crt" in c for c in joined)
    assert any("x509 -req" in c and "server.crt" in c for c in joined)
    # SAN ext file written so the cert covers localhost + 127.0.0.1
    ext = (lab / "server.ext").read_text(encoding="utf-8")
    assert "DNS:localhost" in ext and "IP:127.0.0.1" in ext


def test_extfile_has_the_ini_section_header(lab, monkeypatch):
    # Regression: `x509 -extensions subjectAltName` reads an INI-style extfile.
    # A bare `subjectAltName=...` line makes OpenSSL 3.x fail with
    # "Error checking extension section subjectAltName", so the server cert was
    # never produced. The section header must be present and must match the
    # -extensions value passed to openssl.
    calls = _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    ext = (lab / "server.ext").read_text(encoding="utf-8")
    assert ext.splitlines()[0] == f"[{tls_lab.SERV_EXT_SECTION}]"
    assert f"{tls_lab.SERV_EXT_SECTION}={tls_lab.SERV_ALTNAMES}" in ext
    sign = next(c for c in calls if "x509" in c and "-req" in c)
    assert sign[sign.index("-extensions") + 1] == tls_lab.SERV_EXT_SECTION


def test_stale_extfile_without_section_is_repaired(lab, monkeypatch):
    # A previously-generated (broken) extfile must be rewritten, otherwise the
    # `if not SERV_CNF.exists()` guard would keep the unusable file forever.
    lab.mkdir(parents=True, exist_ok=True)
    (lab / "server.ext").write_text("subjectAltName=DNS:localhost\n", encoding="utf-8")
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    ext = (lab / "server.ext").read_text(encoding="utf-8")
    assert ext.startswith("[")
    assert tls_lab.SERV_EXT_SECTION in ext
    # key+cert bundled for socat
    assert (lab / "server.pem").exists()


def test_setup_is_idempotent(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    second = _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    # nothing regenerated: all files already exist
    assert second == []


def test_setup_reports_the_failing_step(lab, monkeypatch):
    # Regression guard: openssl return codes must not be silently ignored.
    monkeypatch.setattr(tls_lab, "_which", lambda t: "/usr/bin/openssl")
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: False)

    def run(cmd, timeout=60):
        if "-out" in cmd:
            Path(cmd[cmd.index("-out") + 1]).write_text("x", encoding="utf-8")
        if "-x509" in cmd:  # CA cert generation blows up
            return 1
        return 0

    monkeypatch.setattr(tls_lab, "_run", run)
    r = tls_lab.setup_ca()
    assert r["ok"] is False
    assert "openssl failed" in r["error"]
    assert "CA cert" in r["error"]


def test_setup_tells_you_to_install_the_ca(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    r = tls_lab.setup_ca()
    # ready is False until the CA is trusted -> the response must say so.
    assert r["ready"] is False
    # pin the real route: the hint once pointed at a nonexistent /tls/install
    assert "POST /api/net/tls/trust" in r["next"]


def test_status_reports_availability(lab, monkeypatch):
    monkeypatch.setattr(tls_lab, "_which", lambda t: None)
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: False)
    s = tls_lab.status()
    assert s["available"] is False
    assert s["ready"] is False


def test_status_ready_when_everything_present(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: True)
    s = tls_lab.status()
    assert s["available"] is True
    assert s["ca_installed"] is True
    assert s["ready"] is True
    assert "next" not in s


def test_status_tells_you_to_trust_when_built_but_untrusted(lab, monkeypatch):
    # built != ready: the certs exist, only CA trust is missing, so the next
    # step must be the trust call (not a rebuild).
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    s = tls_lab.status()
    assert s["ready"] is False
    assert "trust" in s["next"]


def test_status_tells_you_to_setup_before_setup(lab, monkeypatch):
    monkeypatch.setattr(tls_lab, "_which", lambda t: "/usr/bin/openssl")
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: False)
    s = tls_lab.status()
    assert s["ready"] is False
    assert "setup" in s["next"]


def test_install_requires_setup_first(lab, monkeypatch):
    r = tls_lab.install_ca_to_trust()
    assert r["ok"] is False
    assert "setup" in r["error"]


def test_install_requires_update_ca_certificates(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    monkeypatch.setattr(tls_lab, "_which", lambda t: None)
    r = tls_lab.install_ca_to_trust()
    assert r["ok"] is False
    assert "update-ca-certificates" in r["error"]


def test_install_copies_ca_and_reports(lab, monkeypatch, tmp_path):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    anchors = tmp_path / "anchors"
    monkeypatch.setattr(tls_lab, "_which", lambda t: f"/usr/bin/{t}")
    monkeypatch.setattr(
        tls_lab,
        "Path",
        lambda p: anchors if p == "/usr/local/share/ca-certificates" else Path(p),
    )
    monkeypatch.setattr(tls_lab, "_ca_trusted", lambda: True)
    monkeypatch.setattr(tls_lab, "_run", lambda cmd, timeout=60: 0)
    r = tls_lab.install_ca_to_trust()
    assert r["ok"] is True
    assert r["ca_installed"] is True
    assert (anchors / "h4k-lab-ca.crt").exists()


def test_proxy_requires_setup(lab, monkeypatch):
    r = tls_lab.start_https_proxy()
    assert r["ok"] is False
    assert "TLS setup" in r["error"]


def test_proxy_requires_socat(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    monkeypatch.setattr(tls_lab, "_which", lambda t: None)
    r = tls_lab.start_https_proxy()
    assert r["ok"] is False
    assert "socat" in r["error"]


def test_proxy_starts_loopback_only(lab, monkeypatch):
    _pretend_openssl_ok(monkeypatch, [])
    tls_lab.setup_ca()
    monkeypatch.setattr(tls_lab, "_which", lambda t: f"/usr/bin/{t}")
    # Simulate the forked child: it calls setsid + Popen then _exit(0).
    # _exit is neutered so we can assert on the spawned argv safely.
    monkeypatch.setattr(tls_lab.os, "fork", lambda: 0)
    monkeypatch.setattr(tls_lab.os, "setsid", lambda: None)
    monkeypatch.setattr(tls_lab.os, "_exit", lambda code: None)
    spawned = {}

    def popen(cmd, **kw):
        spawned["cmd"] = cmd
        return None

    monkeypatch.setattr(tls_lab.subprocess, "Popen", popen)
    r = tls_lab.start_https_proxy(listen_port=9443, backend_port=8081)
    assert r["ok"] is True
    assert r["listening"] == "https://127.0.0.1:9443"
    assert r["backend"] == "http://127.0.0.1:8081"
    # the listener must bind loopback, never 0.0.0.0
    assert "bind=127.0.0.1" in spawned["cmd"][1]
    assert "0.0.0.0" not in " ".join(spawned["cmd"])
    assert "tcp:127.0.0.1:8081" in spawned["cmd"][2]


def test_run_reports_missing_binary(monkeypatch):
    rc = tls_lab._run(["definitely-not-real-xyz"])
    assert rc == -1


def test_run_reports_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="openssl", timeout=1)

    monkeypatch.setattr(tls_lab.subprocess, "run", boom)
    assert tls_lab._run(["openssl", "version"]) == -1


def test_run_returns_openssl_returncode(monkeypatch):
    class P:
        returncode = 3
        stderr = "bad option"

    monkeypatch.setattr(tls_lab.subprocess, "run", lambda *a, **k: P())
    assert tls_lab._run(["openssl", "genrsa"]) == 3


def test_next_hints_reference_routes_that_exist():
    """The `next` hint is only actionable if the route it names actually exists.

    A drift guard: the hint once pointed at `/api/net/tls/install`, a route that
    was never registered, so the one piece of advice we gave was a 404.
    """
    from routers import net

    paths = {r.path for r in net.router.routes}
    lab = tls_lab.status()
    hints = [lab["next"]] if "next" in lab else []
    hints.append(tls_lab.setup_ca.__doc__ or "")
    for route in ("/api/net/tls/setup", "/api/net/tls/trust"):
        assert route in paths
    assert not any("install" in h for h in hints if h)
