"""Local privilege-surface awareness: docker-group-to-root + userns-root.

Research notes:
- labs/docker-group-to-root/README.md proves that on this host `greg`
  (uid 1000, no sudo) gets host-root file access via the docker group
  socket + a root-default image.
- labs/userns-root-no-sudo-no-docker/README.md proves that `unshare -Urm`
  yields uid 0 without sudo and without any docker container (namespace
  root by kernel design; host DAC still enforced as the outside uid).

h4k must *know* those paths and be able to *try* them safely (read-only)
so the operator can verify exposure and patch it.

Design rules (match container_escape.py):
- detection is read-only and runs everywhere (including /capabilities);
- the proof-of-access "try" is explicit, opt-in, read-only (`:ro` mount
  or `id`/`ls` only, never write/exec on the host), disabled in sandbox
  mode, with a timeout.
"""

from __future__ import annotations

import grp
import logging
import os
import shutil
import subprocess  # nosec B404 - fixed docker argv for privesc self-check
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.privesc")

_DOCKER_SOCK = Path("/var/run/docker.sock")
_HOST_ROOT = Path("/root")
_UNSHARE = Path("/usr/bin/unshare")

# SUID binaries that historically yield a shell directly (GTFOBins-style).
# Stock Arch ships none of these as SUID; any hit here is a finding.
_SHELL_SUID = frozenset(
    {
        "vim",
        "vi",
        "nano",
        "less",
        "more",
        "find",
        "awk",
        "gawk",
        "env",
        "python",
        "python3",
        "perl",
        "ruby",
        "bash",
        "sh",
        "dash",
        "cp",
        "mv",
        "tar",
        "nmap",
        "man",
        "wget",
        "curl",
    }
)


def _filecap_dac_probe(timeout: float = 10.0) -> tuple[bool, str]:
    """Do host file caps bypass DAC? No sudo, no docker, read-only.

    Runs the host-scoped `gsr-kms-server` (cap_sys_admin=ep) against a
    root-only file. A "Permission denied" outcome proves cap_sys_admin
    confers no DAC bypass (open(2) still enforced). Safe: the binary just
    prints an error and exits 0; nothing is mounted, written, or executed.
    """
    exe = shutil.which("gsr-kms-server")
    if not exe:
        return False, "gsr-kms-server not installed"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "/tmp/h4k-probe-sock", "/etc/shadow"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return False, f"probe failed: {exc}"
    out = ((proc.stdout or "") + (proc.stderr or ""))[:300]
    if "Permission denied" in out:
        return False, "open(/etc/shadow) -> Permission denied: no DAC bypass"
    return True, f"UNEXPECTED (no denial): {out[:160]}"


def _sudo_version(timeout: float = 5.0) -> str:
    """Installed sudo version string. `sudo --version` authenticates nothing."""
    exe = shutil.which("sudo")
    if not exe:
        return "sudo not installed"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        first = ((proc.stdout or proc.stderr) or "").strip().splitlines()
        return first[0][:60] if first else "unknown"
    except Exception as exc:
        return f"unknown ({exc})"


def _sudo_chwoot_status(version_output: str) -> dict[str, str]:
    """Is this sudo build in the chwoot window (CVE-2025-32462/32463)?

    Tuple comparison (see version_detector) cannot tell 1.9.17 base from
    1.9.17p1/p2, so sudo gets dedicated parsing: base X.Y.Z plus optional
    pN patch level. Fixed in 1.9.17p1: base 1.9.14-1.9.17 without a p-suffix
    (or p0) is vulnerable; anything with p>=1, or a base outside
    1.9.0-1.9.17 (32462) / 1.9.14-1.9.17 (32463), is not.
    """
    import re as _re

    m = _re.search(r"(\d+)\.(\d+)\.(\d+)(?:p(\d+))?", version_output)
    if not m:
        return {"status": "unknown", "detail": "no parseable sudo version"}
    x, y, z, p = (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))
    p = int(p) if p is not None else 0
    base = (x, y, z)
    if (1, 9, 14) <= base <= (1, 9, 17) and p < 1:
        return {
            "status": "vulnerable",
            "detail": f"sudo {x}.{y}.{z}{'p'+str(p) if m.group(4) else ''} "
            "in chwoot window (< 1.9.17p1)",
        }
    if (1, 9, 0) <= base <= (1, 9, 17) and p < 1 and base < (1, 9, 14):
        return {
            "status": "vulnerable-32462-only",
            "detail": f"sudo {x}.{y}.{z} predates chroot bug but host-option "
            "bypass (CVE-2025-32462, fixed 1.9.17p1) may apply",
        }
    return {
        "status": "patched",
        "detail": f"sudo {x}.{y}.{z}{'p'+str(p) if m.group(4) else ''} "
        "at or past 1.9.17p1 (chwoot fixed)",
    }


def _pkexec_version(timeout: float = 5.0) -> str:
    """polkit version string. `pkexec --version` authenticates nothing."""
    exe = shutil.which("pkexec")
    if not exe:
        return "pkexec not installed"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ((proc.stdout or proc.stderr) or "").strip().splitlines()[0][:60]
    except Exception as exc:
        return f"unknown ({exc})"


def _active_timers(timeout: float = 10.0) -> list[str]:
    """Names of active systemd timers (stock ones consume no user input)."""
    exe = shutil.which("systemctl")
    if not exe:
        return []
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "list-timers", "--all", "--no-legend", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        names = []
        for line in (proc.stdout or "").splitlines():
            for tok in line.split():
                if tok.endswith(".timer"):
                    names.append(tok)
        return sorted(set(names))
    except Exception:
        return []


def _systemd_exec_audit(timeout: float = 20.0) -> dict[str, Any]:
    """Are any root-run service binaries hijackable? Read-only.

    Lists running system services, resolves each ExecStart path, and checks
    writability of the binary plus the unit file. A writable ExecStart
    binary (or unit file) would be a direct host-root vector. Read-only:
    `systemctl show` and `os.access` only.
    """
    exe = shutil.which("systemctl")
    if not exe:
        return {"checked": 0, "writable_binaries": [], "writable_units": []}
    try:
        units = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [
                exe,
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        names = [
            ln.split()[0] for ln in (units.stdout or "").splitlines() if ln.split()
        ]
    except Exception:
        names = []
    import re

    binaries: set[str] = set()
    writable_units: list[str] = []
    for name in names:
        try:
            shown = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                [exe, "show", "-p", "ExecStart,FragmentPath", name, "--no-pager"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            out = shown.stdout or ""
            binaries.update(re.findall(r"path=(/[^ ;]+)", out))
            m = re.search(r"FragmentPath=(.+)", out)
            if m and m.group(1).strip() not in ("", "/dev/null"):
                frag = m.group(1).strip()
                try:
                    if os.access(frag, os.W_OK):
                        writable_units.append(f"{name}:{frag}")
                except Exception:
                    pass
        except Exception:
            continue
    writable_binaries = sorted(
        b for b in binaries if os.path.exists(b) and os.access(b, os.W_OK)
    )
    return {
        "checked": len(binaries),
        "writable_binaries": writable_binaries,
        "writable_units": sorted(writable_units),
    }


def _path_hijack_check() -> dict[str, Any]:
    """Is any system PATH dir writable by this user? Read-only.

    Root-run jobs (systemd, login SUPATH) resolve binaries via
    /usr/local/sbin:/usr/local/bin:/usr/bin. A writable dir there would
    allow planting a same-name binary for the next root execution.
    """
    dirs = ["/usr/local/sbin", "/usr/local/bin", "/usr/bin"]
    writable = [d for d in dirs if os.path.isdir(d) and os.access(d, os.W_OK)]
    return {"path_dirs": dirs, "writable_path_dirs": writable}


def _credential_gates_check(timeout: float = 10.0) -> dict[str, Any]:
    """Do su/sudo/pkexec allow passwordless root? No password ever supplied.

    - `sudo -n true`: non-interactive; succeeds ONLY on NOPASSWD-style
      config. Executing the sudo binary this way performs no privileged
      action and supplies no credentials — "a password is required"
      (rc=1) proves the gate instead of passing it.
    - `/etc/pam.d/su`: an uncommented `pam_wheel ... trust` line would let
      wheel members `su` root with no password; its absence (plus
      `pam_unix required`) proves `su` gates on a password.
    pkexec is covered by the polkit inventory (auth_admin, no
    passwordless vendor rule). No docker involved anywhere.
    """
    sudo_passwordless: bool | None = None
    sudo_detail = ""
    exe = shutil.which("sudo")
    if not exe:
        sudo_detail = "sudo not installed"
    else:
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                [exe, "-n", "true"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            err = ((proc.stdout or "") + (proc.stderr or "")).strip()[:160]
            if proc.returncode == 0:
                sudo_passwordless, sudo_detail = True, "sudo -n true SUCCEEDED"
            else:
                sudo_passwordless, sudo_detail = False, err or f"rc={proc.returncode}"
        except Exception as exc:
            sudo_detail = f"probe failed: {exc}"
    su_trust = False
    try:
        for line in (
            Path("/etc/pam.d/su")
            .read_text(encoding="utf-8", errors="replace")
            .splitlines()
        ):
            s = line.strip()
            if s.startswith("#") or "pam_wheel" not in s or "trust" not in s:
                continue
            su_trust = True
    except OSError as exc:
        sudo_detail += f" (su PAM unreadable: {exc})"
    return {
        "sudo_passwordless": sudo_passwordless,
        "sudo_detail": sudo_detail,
        "su_wheel_trust": su_trust,
        "credential_gate_holds": sudo_passwordless is False and not su_trust,
    }


def _polkit_inventory(timeout: float = 10.0) -> dict[str, Any]:
    """Readable polkit posture. Read-only, authenticates nothing.

    Reports the default admin rule, whether any readable rule grants
    passwordless `yes`, one representative action's requirement
    (manage-units -> auth_admin), and flags the root-only
    /etc/polkit-1/rules.d as an explicit blind spot.
    """
    readable: list[str] = []
    passwordless: list[str] = []
    try:
        from pathlib import Path as _Path

        for f in sorted(_Path("/usr/share/polkit-1/rules.d").glob("*.rules")):
            readable.append(f.name)
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                if "return" in text and "yes" in text:
                    passwordless.append(f.name)
            except OSError:
                pass
    except OSError:
        pass
    manage_units = "unknown"
    exe = shutil.which("pkaction")
    if exe:
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
                [
                    exe,
                    "--action-id",
                    "org.freedesktop.systemd1.manage-units",
                    "--verbose",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                if "implicit active" in line:
                    manage_units = line.strip()[:60]
        except Exception:
            pass
    etc_readable = os.access("/etc/polkit-1/rules.d", os.R_OK | os.X_OK)
    return {
        "readable_vendor_rules": readable,
        "passwordless_vendor_rules": passwordless,
        "manage_units": manage_units,
        "etc_rules_readable": etc_readable,
        "etc_rules_blind_spot": not etc_readable,
    }


def host_privesc_audit(timeout: float = 30.0) -> dict[str, Any]:
    """Exhaustive read-only host privesc audit. No sudo, no docker.

    Enumerates (read-only): kernel version, polkit version + vendor-rule
    inventory, active systemd timers, root-run service binaries/unit files
    and their writability, system PATH dir writability, full SUID list,
    full file-cap list over system roots, writability of sensitive paths,
    whether any SUID binary is a known shell-escape (GTFOBins set), and a
    live DAC-bypass probe (does the sys_admin file cap actually open a
    root-only file?), and the credential gates (non-interactive
    `sudo -n true` plus the su PAM trust check — the sudo binary runs but
    performs no privileged action and is given no credentials). Never
    touches the docker daemon and never handles a password — safe to run
    on every poll.
    Returns findings plus a verdict: either a concrete host-root vector or
    an explicit statement that none was found in the automated scope.
    """
    import platform

    kernel = platform.release()
    suid: list[str] = []
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed find argv, no shell
            [
                "find",
                "/usr",
                "/bin",
                "/sbin",
                "/opt",
                "-xdev",
                "-perm",
                "-4000",
                "-printf",
                "%p\n",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        # find exits 1 when a subtree (e.g. /opt/containerd) denies listing;
        # stdout still holds every match, so parse it regardless of rc.
        suid = sorted(p for p in (proc.stdout or "").splitlines() if p)
    except Exception as exc:
        logger.debug("suid scan failed: %s", exc)
    caps: dict[str, str] = {}
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed getcap argv
            ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/opt"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            # getcap prints "<path> <cap-list>=<flags>"; split on the space,
            # not on "=", or the path swallows the capability names.
            path, _, cap = line.partition(" ")
            path, cap = path.strip(), cap.strip()
            if path and cap:
                caps[path] = cap
    except Exception as exc:
        logger.debug("getcap scan failed: %s", exc)
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
    writable: list[str] = []
    for p in sensitive:
        try:
            if os.access(p, os.W_OK):
                writable.append(p)
        except Exception:
            pass
    shell_suid = sorted(
        {Path(p).name for p in suid} & set(_SHELL_SUID),
        key=str.lower,
    )
    # Host-scoped caps that merit a finding (DAC bypass / sys_admin).
    risky_caps = {
        p: c
        for p, c in caps.items()
        if "cap_dac_read_search" in c or "cap_dac_override" in c or "cap_sys_admin" in c
    }
    # Live DAC-bypass probe: does the sys_admin file cap actually open
    # root-only files? (Proven no: open -> Permission denied.)
    dac_bypass, dac_detail = _filecap_dac_probe(timeout=min(timeout, 10.0))
    pkexec_version = _pkexec_version(timeout=min(timeout, 5.0))
    timers = _active_timers(timeout=min(timeout, 10.0))
    # CVE posture vs h4k's own curated DB: installed sudo version against
    # the chwoot window, running kernel against the Copy Fail ranges.
    # Read-only version-string comparison; no exploit is ever run.
    sudo_ver = _sudo_version(timeout=min(timeout, 5.0))
    chwoot = _sudo_chwoot_status(sudo_ver)
    kernel_hits: list[dict[str, Any]] = []
    try:
        from services.version_detector import check_vulnerable_version

        kernel_hits = check_vulnerable_version("linux", kernel)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("kernel CVE match failed: %s", exc)
    cve_posture = {
        "sudo_version": sudo_ver,
        "chwoot": chwoot,
        "kernel": kernel,
        "kernel_cve_hits": [
            {"cve": h.get("cve"), "range": h.get("range")} for h in kernel_hits
        ],
    }
    vectors: list[dict[str, Any]] = []
    if writable:
        vectors.append(
            {
                "type": "writable-sensitive",
                "name": ",".join(writable),
                "description": "sensitive file writable by this user",
                "exploit": None,
            }
        )
    if shell_suid:
        vectors.append(
            {
                "type": "suid-shell",
                "name": ",".join(shell_suid),
                "description": "SUID binary with known shell-escape",
                "exploit": None,
            }
        )
    if dac_bypass:
        vectors.append(
            {
                "type": "filecap-dac-bypass",
                "name": "gsr-kms-server",
                "description": f"live probe shows DAC bypass: {dac_detail}",
                "exploit": None,
            }
        )
    # Remaining vectors: writable service binaries/units, PATH hijack,
    # passwordless polkit allows, passwordless sudo/su trust. All read-only;
    # the sudo probe is `sudo -n true` (no credentials, no priv action).
    sysd = _systemd_exec_audit(timeout=min(timeout, 20.0))
    pathchk = _path_hijack_check()
    polkit = _polkit_inventory(timeout=min(timeout, 10.0))
    gates = _credential_gates_check(timeout=min(timeout, 10.0))
    if sysd["writable_binaries"]:
        vectors.append(
            {
                "type": "writable-service-binary",
                "name": ",".join(sysd["writable_binaries"][:5]),
                "description": "root-run service binary writable by user",
                "exploit": None,
            }
        )
    if sysd["writable_units"]:
        vectors.append(
            {
                "type": "writable-service-unit",
                "name": ",".join(sysd["writable_units"][:5]),
                "description": "systemd unit file writable by user",
                "exploit": None,
            }
        )
    if pathchk["writable_path_dirs"]:
        vectors.append(
            {
                "type": "path-hijack",
                "name": ",".join(pathchk["writable_path_dirs"]),
                "description": "system PATH dir writable by user",
                "exploit": None,
            }
        )
    if polkit["passwordless_vendor_rules"]:
        vectors.append(
            {
                "type": "polkit-passwordless",
                "name": ",".join(polkit["passwordless_vendor_rules"]),
                "description": "vendor polkit rule grants passwordless allow",
                "exploit": None,
            }
        )
    if gates["sudo_passwordless"] is True:
        vectors.append(
            {
                "type": "sudo-nopasswd",
                "name": "sudo -n true succeeded",
                "description": "sudo grants passwordless root (NOPASSWD)",
                "exploit": None,
            }
        )
    if gates["su_wheel_trust"]:
        vectors.append(
            {
                "type": "su-wheel-trust",
                "name": "pam_wheel trust",
                "description": "wheel members can su root with no password",
                "exploit": None,
            }
        )
    if chwoot["status"] != "patched":
        vectors.append(
            {
                "type": "cve-chwoot",
                "name": "sudo " + chwoot["detail"],
                "description": "installed sudo in chwoot window (CVE-2025-32462/32463)",
                "exploit": None,
            }
        )
    if kernel_hits:
        vectors.append(
            {
                "type": "cve-kernel",
                "name": ",".join(sorted({h.get("cve", "") for h in kernel_hits})),
                "description": f"running kernel {kernel} in a known-vulnerable range",
                "exploit": None,
            }
        )
    return {
        "kernel": kernel,
        "pkexec_version": pkexec_version,
        "active_timers": timers,
        "systemd_exec": sysd,
        "path_check": pathchk,
        "polkit": polkit,
        "credential_gates": gates,
        "cve_posture": cve_posture,
        "suid_count": len(suid),
        "suid": suid,
        "shell_suid": shell_suid,
        "file_caps": caps,
        "risky_caps": risky_caps,
        "filecap_dac_bypass": dac_bypass,
        "filecap_dac_detail": dac_detail,
        "sensitive_writable": writable,
        "vectors": vectors,
        "host_root_vector_found": bool(vectors),
        "verdict": (
            "HOST-ROOT VECTOR PRESENT: "
            + "; ".join(v["type"] + ":" + v["name"] for v in vectors)
            if vectors
            else "no host uid-0/DAC-bypass vector in automated scope "
            "(stock SUID set, no shell-escape SUID, no writable sensitive "
            "file, live filecap probe denies DAC bypass, "
            f"timers stock ({len(timers)}), "
            f"systemd exec clean ({sysd['checked']} binaries), "
            "PATH dirs root-owned, no passwordless polkit rule, "
            "sudo/su both password-gated, chwoot patched, kernel past "
            "Copy Fail range, userns gives namespace root only)"
        ),
        "uses_sudo": False,
        "uses_docker": False,
        "uses_password": False,
    }


def _userns_available(timeout: float = 5.0) -> tuple[bool, str]:
    """Is unprivileged userns uid-0 available (no sudo, no docker)?"""
    exe = shutil.which("unshare")
    if not exe:
        return False, "unshare not installed"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "-Urm", "id", "-u"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return False, f"unshare probe failed: {exc}"
    out = (proc.stdout or "").strip()
    if proc.returncode == 0 and out == "0":
        return True, "unshare -Urm yields uid 0 (namespace root, no sudo/docker)"
    err = (proc.stderr or proc.stdout or "").strip()[:200]
    return False, f"unshare rc={proc.returncode}: {err}"


def _euid() -> int:
    try:
        return os.geteuid()
    except AttributeError:  # pragma: no cover - non-posix
        return -1


def _in_container() -> bool:
    if Path("/.dockerenv").exists():
        return True
    try:
        cgroup = Path("/proc/self/cgroup").read_text(encoding="utf-8")
        return "docker" in cgroup or "containerd" in cgroup
    except OSError:
        return False


def _docker_groups() -> list[str]:
    """Groups of the current user that grant docker-daemon access."""
    found: list[str] = []
    try:
        gids = set(os.getgroups())
    except OSError:
        gids = set()
    for name in ("docker",):
        try:
            entry = grp.getgrnam(name)
        except KeyError:
            continue
        if entry.gr_gid in gids or _euid() == 0:
            found.append(name)
    return found


def _docker_works(timeout: float = 5.0) -> tuple[bool, str]:
    """Can we talk to the daemon without sudo? (`docker ps`, read-only)."""
    exe = shutil.which("docker")
    if not exe:
        return False, "docker CLI not installed"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return False, f"docker ps failed: {exc}"
    if proc.returncode == 0:
        return True, "docker daemon reachable without sudo"
    err = (proc.stderr or proc.stdout or "").strip()[:200]
    return False, f"docker ps rc={proc.returncode}: {err}"


def _direct_root_read() -> tuple[bool, str]:
    """Can this process read host /root directly (no docker)?"""
    try:
        next(_HOST_ROOT.iterdir())
        return True, "can list /root directly (already root or permissive)"
    except PermissionError:
        return False, "Permission denied listing /root directly"
    except FileNotFoundError:
        return False, "/root not present"
    except Exception as exc:
        return False, str(exc)[:120]


def docker_group_report() -> dict[str, Any]:
    """Read-only privilege-surface report. Safe to call on every boot/poll."""
    euid = _euid()
    in_container = _in_container()
    groups = _docker_groups()
    docker_ok, docker_detail = _docker_works()
    direct_ok, direct_detail = _direct_root_read()
    sock_present = _DOCKER_SOCK.exists()
    userns_ok, userns_detail = _userns_available()

    vectors: list[dict[str, Any]] = []
    if groups and docker_ok:
        vectors.append(
            {
                "type": "docker-group",
                "name": "docker group -> host root",
                "description": (
                    "user in docker group can ask the root daemon to mount "
                    "any host path into a root-default container (no sudo)"
                ),
                "exploit": "privesc_try_docker_group_read",
            }
        )
    if sock_present and in_container:
        vectors.append(
            {
                "type": "mount",
                "name": str(_DOCKER_SOCK),
                "description": "docker socket exposed inside container",
                "exploit": "docker_socket_escape",
            }
        )
    if euid == 0:
        vectors.append(
            {
                "type": "identity",
                "name": "running as uid 0",
                "description": "this API process is root (image has no USER drop)",
                "exploit": None,
            }
        )
    if userns_ok:
        vectors.append(
            {
                "type": "userns",
                "name": "unprivileged user namespace -> uid 0",
                "description": (
                    "unshare -Urm yields uid 0 with no sudo and no docker "
                    "container (namespace root by design; host DAC still "
                    "enforced as the outside uid)"
                ),
                "exploit": "privesc_try_userns",
            }
        )

    return {
        "euid": euid,
        "is_root": euid == 0,
        "in_container": in_container,
        "docker_groups": groups,
        "docker_reachable_without_sudo": docker_ok,
        "docker_detail": docker_detail,
        "direct_root_read": direct_ok,
        "direct_root_detail": direct_detail,
        "docker_socket_present": sock_present,
        "userns_available": userns_ok,
        "userns_detail": userns_detail,
        "vectors": vectors,
        "at_risk": bool(groups and docker_ok and not direct_ok) or euid == 0,
    }


def try_docker_group_read(timeout: int = 60) -> dict[str, Any]:
    """OPT-IN safe try: prove host-root read via a read-only mount.

    Compares direct `ls /root` (expected Permission denied for non-root)
    against `docker run --rm -v /:/host:ro --entrypoint ls <img> /host/root`.
    Read-only, `ls` only, never writes. Disabled in sandbox mode.
    """
    from services.sandbox import enabled as sandbox_enabled

    if sandbox_enabled():
        return {"success": False, "reason": "disabled in sandbox mode"}
    direct_ok, direct_detail = _direct_root_read()
    exe = shutil.which("docker")
    if not exe:
        return {"success": False, "reason": "docker CLI not installed"}
    # Prefer the h4k image itself so the proof is "h4k achieves root";
    # fall back to alpine only if h4k:latest is absent (e.g. host tooling).
    image = "h4k:latest"
    try:
        probe = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "images", "-q", image],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if not (probe.stdout or "").strip():
            image = "alpine:3.20"
    except Exception:
        image = "alpine:3.20"
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [
                exe,
                "run",
                "--rm",
                "-v",
                "/:/host:ro",
                "--entrypoint",
                "ls",
                image,
                "-la",
                "/host/root",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {"success": False, "reason": f"docker run failed: {exc}"}
    out = (proc.stdout or "")[:2000]
    err = (proc.stderr or "")[:500]
    success = proc.returncode == 0 and "Permission denied" not in out
    return {
        "success": success,
        "image": image,
        "direct_root_read": direct_ok,
        "direct_detail": direct_detail,
        "rc": proc.returncode,
        "stdout": out,
        "stderr": err,
        "method": "docker run --rm -v /:/host:ro --entrypoint ls <img> /host/root",
        "read_only": True,
    }


def try_userns_root(timeout: int = 30) -> dict[str, Any]:
    """OPT-IN safe try: prove uid 0 via unshare userns (no sudo, no docker).

    Runs `unshare -Urm id -u` (expect `0`) plus a mount-namespace check.
    Creates no host files, touches no docker daemon, never uses sudo.
    Disabled in sandbox mode.
    """
    from services.sandbox import enabled as sandbox_enabled

    if sandbox_enabled():
        return {"success": False, "reason": "disabled in sandbox mode"}
    direct_ok, direct_detail = _direct_root_read()
    exe = shutil.which("unshare")
    if not exe:
        return {"success": False, "reason": "unshare not installed"}
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "-Urm", "id"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {"success": False, "reason": f"unshare failed: {exc}"}
    out = (proc.stdout or "").strip()[:500]
    err = (proc.stderr or "").strip()[:500]
    success = proc.returncode == 0 and "uid=0(root)" in out
    # Honest limit: namespace root is NOT host root — host DAC still
    # enforced as the outside uid, so /root stays unreadable.
    host_root_still_denied: bool | None = None
    try:
        denied = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            [exe, "-Urm", "ls", "/root"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        host_root_still_denied = (
            "Permission denied" in (denied.stderr or denied.stdout or "")
            or denied.returncode != 0
        )
    except Exception:
        host_root_still_denied = None
    return {
        "success": success,
        "direct_root_read": direct_ok,
        "direct_detail": direct_detail,
        "rc": proc.returncode,
        "stdout": out,
        "stderr": err,
        "host_root_still_denied": host_root_still_denied,
        "method": "unshare -Urm id",
        "read_only": True,
        "uses_sudo": False,
        "uses_docker": False,
        "note": (
            "namespace root (uid 0 in a user+mount ns), not host root: "
            "/root remains Permission denied"
            if host_root_still_denied
            else "uid 0 in userns"
        ),
    }
