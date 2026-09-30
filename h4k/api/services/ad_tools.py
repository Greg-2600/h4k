# AD post-exploitation and network-layer relay tools.
# BloodHound.py for AD mapping, mitm6 for IPv6 relay, responder for NTLM relay.
# All tools require explicit opt-in and authorized scope.
import logging
import subprocess  # nosec B404 - fixed-argv wrapper
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.ad_tools")

BLOODHOUND_PY = "bloodhound-python"
MITM6 = "mitm6"
RESPONDER = "responder3"


class ADToolsService:
    """AD post-exploitation and relay tools wrapper."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 600) -> dict[str, Any]:
        self.progress(f"[ad_tools] {' '.join(argv[:8])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "rc": proc.returncode,
                "success": proc.returncode == 0,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "stdout": _as_text(exc.stdout),
                "stderr": _as_text(exc.stderr),
                "rc": None,
                "success": False,
                "timed_out": True,
            }
        except FileNotFoundError as exc:
            return {
                "stdout": "",
                "stderr": f"{exc.filename} not installed",
                "rc": -1,
                "success": False,
                "timed_out": False,
            }
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "stdout": "",
                "stderr": str(exc),
                "rc": -1,
                "success": False,
                "timed_out": False,
            }

    # ---- BloodHound.py ----
    def bloodhound_collect(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str | None = None,
        collection_method: str = "All",
        output_dir: str | None = None,
        zip_output: bool = True,
    ) -> dict[str, Any]:
        """Run BloodHound.py data collection."""
        argv = [
            BLOODHOUND_PY,
            "-d",
            domain,
            "-u",
            username,
            "-p",
            password,
            "-c",
            collection_method,
        ]
        if dc_ip:
            argv += ["-dc", dc_ip]
        if output_dir:
            argv += ["-o", output_dir]
        if zip_output:
            argv.append("--zip")
        return self._run(argv, timeout=1800)

    # ---- mitm6 ----
    def mitm6_attack(
        self,
        interface: str,
        domain: str | None = None,
        ipv4: str | None = None,
        config_file: str | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run mitm6 for IPv6 MITM/NTLM relay."""
        argv = [MITM6, "-i", interface]
        if domain:
            argv += ["-d", domain]
        if ipv4:
            argv += ["-ipv4", ipv4]
        if config_file:
            argv += ["-c", config_file]
        return self._run(argv, timeout=timeout + 60)

    # ---- Responder ----
    def responder_attack(
        self,
        interface: str,
        analyze_mode: bool = False,
        fingerprint: bool = False,
        http_port: int = 80,
        https_port: int = 443,
        smb_port: int = 445,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Run Responder for NTLM relay/LLMNR/NBNS poisoning."""
        argv = [RESPONDER, "-I", interface]
        if analyze_mode:
            argv.append("-A")
        if fingerprint:
            argv.append("-f")
        argv += ["-h", str(http_port), "-s", str(https_port), "-S", str(smb_port)]
        return self._run(argv, timeout=timeout + 60)

    # ---- Combined relay workflow ----
    def relay_chain(
        self,
        interface: str,
        target_domain: str,
        target_dc_ip: str,
        username: str,
        password: str,
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Combined mitm6 + ntlmrelayx + BloodHound collection."""
        results = {}

        # Start mitm6 in background
        self.progress("Starting mitm6", 10)
        mitm6_result = self.mitm6_attack(interface, timeout=timeout)
        results["mitm6"] = mitm6_result

        # Run ntlmrelayx via responder (simplified)
        # Note: full relay chain needs ntlmrelayx.py from impacket
        self.progress("NTLM relay chain not fully implemented", 50)

        # If relay succeeds, collect BloodHound data
        if mitm6_result.get("success"):
            self.progress("Running BloodHound collection", 70)
            bh_result = self.bloodhound_collect(
                domain=target_domain,
                username="",  # Would need relayed creds
                password="",  # nosec B106 - placeholder for relayed creds
                dc_ip=target_dc_ip,
            )
            results["bloodhound"] = bh_result

        return results


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def bloodhound_collect(
    domain: str, username: str, password: str, **kwargs: Any
) -> dict[str, Any]:
    return ADToolsService().bloodhound_collect(domain, username, password, **kwargs)


def mitm6_attack(interface: str, **kwargs: Any) -> dict[str, Any]:
    return ADToolsService().mitm6_attack(interface, **kwargs)


def responder_attack(interface: str, **kwargs: Any) -> dict[str, Any]:
    return ADToolsService().responder_attack(interface, **kwargs)
