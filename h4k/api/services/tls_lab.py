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
SERV_ALTNAMES = "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"


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


def status() -> dict[str, Any]:
    return {
        "available": _which("openssl") is not None,
        "ca_installed": _ca_trusted(),
        "ca_key": str(CA_KEY),
        "ca_crt": str(CA_CRT),
        "server_cert": str(SERV_CRT),
        "ready": CA_CRT.exists() and SERV_CRT.exists() and _ca_trusted(),
    }


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
    """Create the lab CA + a localhost server cert (idempotent)."""
    if not _which("openssl"):
        return {"ok": False, "error": "openssl not installed"}
    LAB_DIR.mkdir(parents=True, exist_ok=True)

    # 1) CA key + cert
    if not CA_KEY.exists():
        _run([_open_ssl(), "genrsa", "-out", str(CA_KEY), "2048"])
    if not CA_CRT.exists():
        _run(
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
            ]
        )

    # 2) server key signed by the CA for localhost/127.0.0.1
    if not SERV_KEY.exists():
        _run([_open_ssl(), "genrsa", "-out", str(SERV_KEY), "2048"])
    if not SERV_CSR.exists():
        _run(
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
            ]
        )
    # openssl 3.x needs -copy_extensions on x509 for subjectAltName from CSR
    if not SERV_CNF.exists():
        SERV_CNF.write_text(SERV_ALTNAMES + "\n", encoding="utf-8")
    if not SERV_CRT.exists():
        _run(
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
                "subjectAltName",
                "-copy_extensions",
                "copy",
                "-out",
                str(SERV_CRT),
            ]
        )

    # 3) bundle key+crt for socat's openssl s_server -cert
    if SERV_CRT.exists() and SERV_KEY.exists():
        CERT_BUNDLE.write_bytes(SERV_KEY.read_bytes() + SERV_CRT.read_bytes())

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
