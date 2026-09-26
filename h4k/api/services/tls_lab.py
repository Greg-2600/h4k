# Local TLS interception lab (OPT-IN, loopback-only).
#
# For fuzzing/SAST against HTTPS web apps you own, you need a trustable local
# endpoint. This builds, on loopback, a private Certificate Authority, signs a
# cert for localhost/127.0.0.1, installs the CA into the container's trust
# store, and can expose an HTTPS sidecar in front of a plain-HTTP lab target
# (via socat with `openssl s_server`) so your owned HTTPS web app can be
# fuzzed/scanned with a cert clients actually trust.
#
# Everything binds to 127.0.0.1 only and is clearly for sanctioned lab work.
import logging
import os
import shutil
import subprocess  # nosec B404 - runs openssl for local lab TLS
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.tls")

DATA_DIR = Path("/opt/h4k/data")
LAB_DIR = DATA_DIR / "tls-lab"
CA_KEY = LAB_DIR / "ca.key"
CA_CRT = LAB_DIR / "ca.crt"
SERV_KEY = LAB_DIR / "server.key"
SERV_CRT = LAB_DIR / "server.crt"
SERV_CSR = LAB_DIR / "server.csr"
SERV_CNF = LAB_DIR / "server.ext"
CERT_BUNDLE = LAB_DIR / "server.pem"  # key + crt for socat openssl s_server

CA_DN = "/CN=h4k Lab CA"
# `x509 -extensions subjectAltName` reads an INI-style extfile, so the section
# header is mandatory -- a bare `subjectAltName=...` line fails with
# "Error checking extension section subjectAltName" on OpenSSL 3.x.
SERV_EXT_SECTION = "subjectAltName"
SERV_ALTNAMES = "DNS:localhost,IP:127.0.0.1,IP:::1"
SERV_CNF_TEXT = f"[{SERV_EXT_SECTION}]\nsubjectAltName={SERV_ALTNAMES}\n"


def _which(t: str) -> str | None:
    return shutil.which(t)


def _run(cmd: list[str], timeout: int = 60) -> int:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        if proc.returncode != 0:
            logger.warning("openssl step failed: %s", (proc.stderr or "")[:200])
        return proc.returncode
    except FileNotFoundError:
        logger.warning("openssl not installed")
        return -1
    except subprocess.TimeoutExpired:
        logger.warning("openssl step timed out")
        return -1


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _has_ext_section(path: Path) -> bool:
    """True only if the extfile carries the `[<section>]` INI header openssl
    needs. A missing/legacy file is rewritten so setup is self-healing."""
    for line in _read_text(path).splitlines():
        if line.strip().lower() == f"[{SERV_EXT_SECTION.lower()}]":
            return True
    return False


def status() -> dict[str, Any]:
    trusted = _ca_trusted()
    built = CA_CRT.exists() and SERV_CRT.exists()
    out = {
        "available": _which("openssl") is not None,
        "ca_installed": trusted,
        "ca_key": str(CA_KEY),
        "ca_crt": str(CA_CRT),
        "server_cert": str(SERV_CRT),
        "ready": built and trusted,
    }
    if built and not trusted:
        out["next"] = "run POST /api/net/tls/trust to trust the lab CA"
    elif not built:
        out["next"] = "run POST /api/net/tls/setup to build the lab CA + cert"
    return out


def _ca_trusted() -> bool:
    _which_ = _which
    # Debian-style: a hash-symlinked cert in the system anchor dir.
    if _which_("update-ca-certificates"):
        anchors = Path("/usr/local/share/ca-certificates")
        if (anchors / "h4k-lab-ca.crt").exists():
            return True
    return False


def _open_ssl() -> str:
    p = _which("openssl")
    return p or "openssl"


def setup_ca() -> dict[str, Any]:
    """Create the lab CA + a localhost server cert (idempotent).

    Every openssl step's return code is checked, so a genuine failure names the
    step that broke instead of returning a bare `ready: false`.
    """
    if not _which("openssl"):
        return {"ok": False, "error": "openssl not installed"}
    LAB_DIR.mkdir(parents=True, exist_ok=True)

    def step(label: str, cmd: list[str]) -> str | None:
        rc = _run(cmd)
        return None if rc == 0 else label

    # 1) CA key + cert
    if not CA_KEY.exists():
        err = step(
            "genrsa (CA key)", [_open_ssl(), "genrsa", "-out", str(CA_KEY), "2048"]
        )
        if err:
            return {"ok": False, "error": f"openssl failed: {err}"}
    if not CA_CRT.exists():
        err = step(
            "req -x509 (self-signed CA cert)",
            [
                _open_ssl(),
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                str(CA_KEY),
                "-sha256",
                "-days",
                "3650",
                "-out",
                str(CA_CRT),
                "-subj",
                CA_DN,
            ],
        )
        if err:
            return {"ok": False, "error": f"openssl failed: {err}"}

    # 2) server key signed by the CA for localhost/127.0.0.1
    if not SERV_KEY.exists():
        err = step(
            "genrsa (server key)",
            [_open_ssl(), "genrsa", "-out", str(SERV_KEY), "2048"],
        )
        if err:
            return {"ok": False, "error": f"openssl failed: {err}"}
    if not SERV_CSR.exists():
        err = step(
            "req -new (server CSR)",
            [
                _open_ssl(),
                "req",
                "-new",
                "-key",
                str(SERV_KEY),
                "-out",
                str(SERV_CSR),
                "-subj",
                "/CN=localhost",
            ],
        )
        if err:
            return {"ok": False, "error": f"openssl failed: {err}"}
    # openssl 3.x needs -copy_extensions on x509 for subjectAltName from CSR
    if not _has_ext_section(SERV_CNF):
        SERV_CNF.write_text(SERV_CNF_TEXT, encoding="utf-8")
    if not SERV_CRT.exists():
        err = step(
            "x509 -req (sign server cert)",
            [
                _open_ssl(),
                "x509",
                "-req",
                "-in",
                str(SERV_CSR),
                "-CA",
                str(CA_CRT),
                "-CAkey",
                str(CA_KEY),
                "-CAcreateserial",
                "-days",
                "825",
                "-sha256",
                "-extfile",
                str(SERV_CNF),
                "-extensions",
                SERV_EXT_SECTION,
                "-copy_extensions",
                "copy",
                "-out",
                str(SERV_CRT),
            ],
        )
        if err:
            return {"ok": False, "error": f"openssl failed: {err}"}

    # 3) bundle key+crt for socat's openssl s_server -cert
    if SERV_CRT.exists() and SERV_KEY.exists():
        CERT_BUNDLE.write_bytes(SERV_KEY.read_bytes() + SERV_CRT.read_bytes())
    else:  # pragma: no cover - defensive; steps above would have returned
        return {"ok": False, "error": "server key/cert missing after signing"}

    # `ready` also requires the CA to be trusted, a separate opt-in step;
    # status() attaches the `next` action for that so a `ready: false` here is
    # never mistaken for a setup failure.
    return status()


def install_ca_to_trust() -> dict[str, Any]:
    """Install the lab CA into the container's trust store (opt-in, lab)."""
    if not CA_CRT.exists():
        return {"ok": False, "error": "run setup first (no CA yet)"}
    if not _which("update-ca-certificates"):
        return {"ok": False, "error": "update-ca-certificates not available"}
    anchor_dir = Path("/usr/local/share/ca-certificates")
    anchor_dir.mkdir(parents=True, exist_ok=True)
    dest = anchor_dir / "h4k-lab-ca.crt"
    if not dest.exists():
        shutil.copy(CA_CRT, dest)
    rc = _run(["update-ca-certificates", "--fresh"], timeout=90)
    return {"ok": rc == 0, "ca_installed": _ca_trusted(), "cert": str(dest)}


def start_https_proxy(
    listen_port: int = 8443,
    backend_host: str = "127.0.0.1",
    backend_port: int = 8080,
) -> dict[str, Any]:
    """Expose an owned plain-HTTP lab target over loopback HTTPS.

    socat with `openssl s_server` terminates TLS on 127.0.0.1:listen_port and
    forwards plain HTTP to backend_host:backend_port. Only binds loopback.
    """
    if not (SERV_CRT.exists() and SERV_KEY.exists()):
        return {"ok": False, "error": "run TLS setup first"}
    socat = _which("socat")
    if not socat:
        return {"ok": False, "error": "socat required"}
    listen_addr = (
        f"openssl-listen:{listen_port},bind=127.0.0.1,reuseaddr,cert={CERT_BUNDLE},"
        "verify=0,fork"
    )
    target = f"tcp:{backend_host}:{backend_port}"
    # Spawn the listener in the background (own session) so this call returns
    # immediately; the proxy keeps running for the operator's lab session.
    pid = os.fork()
    if pid == 0:
        os.setsid()
        subprocess.Popen(  # nosec B603 B607 - fixed argv, no shell
            [socat, listen_addr, target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        os._exit(0)
    return {
        "ok": True,
        "listening": f"https://127.0.0.1:{listen_port}",
        "backend": f"http://{backend_host}:{backend_port}",
        "note": "loopback TLS proxy started; point the fuzzer/SAST at the "
        "https URL. Install the lab CA (from this lab) so clients trust it.",
    }
