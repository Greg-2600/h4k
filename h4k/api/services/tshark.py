# Tshark/Wireshark integration: automated packet capture and analysis.
# For authorized network traffic analysis. Live capture, pcap processing,
# protocol dissection, flow/credential extraction and anomaly detection.
import contextlib
import logging
import os
import subprocess  # nosec B404 - fixed-argv tshark wrapper
import tempfile
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.tshark")

TSHARK = "tshark"
CAPINFOS = "capinfos"
EDITCAP = "editcap"
MERGE_CAP = "mergecap"


class TsharkService:
    """Tshark wrapper for packet capture and analysis."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 300) -> dict[str, Any]:
        self.progress(f"[tshark] {' '.join(argv[:6])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=timeout, check=False
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
        except FileNotFoundError:
            return {
                "stdout": "",
                "stderr": "tshark not installed",
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

    def list_interfaces(self) -> list[dict[str, str]]:
        result = self._run([TSHARK, "-D"])
        interfaces: list[dict[str, str]] = []
        for line in result["stdout"].split("\n"):
            parts = line.split(". ", 1)
            if len(parts) == 2:
                interfaces.append({"id": parts[0], "name": parts[1]})
        return interfaces

    def capture_live(
        self,
        interface: str,
        duration: int = 60,
        filter: str | None = None,
        output: str | None = None,
    ) -> dict[str, Any]:
        argv = [TSHARK, "-i", interface, "-a", f"duration:{duration}"]
        if filter:
            argv += ["-f", filter]
        if output:
            argv += ["-w", output]
        return self._run(argv, timeout=duration + 30)

    def analyze_pcap(
        self,
        pcap_file: str,
        filter: str | None = None,
        fields: list[str] | None = None,
        output_json: bool = True,
    ) -> dict[str, Any]:
        argv = [TSHARK, "-r", pcap_file]
        if filter:
            argv += ["-Y", filter]
        if output_json:
            argv += ["-T", "json"]
        for field in fields or []:
            argv += ["-e", field]
        return self._run(argv, timeout=300)

    def extract_flows(self, pcap_file: str) -> dict[str, Any]:
        """Extract TCP/UDP conversations and endpoints."""
        return {
            "tcp_conversations": self._run([TSHARK, "-r", pcap_file, "-z", "conv,tcp"])[
                "stdout"
            ],
            "udp_conversations": self._run([TSHARK, "-r", pcap_file, "-z", "conv,udp"])[
                "stdout"
            ],
            "tcp_endpoints": self._run(
                [TSHARK, "-r", pcap_file, "-z", "endpoints,tcp"]
            )["stdout"],
            "udp_endpoints": self._run(
                [TSHARK, "-r", pcap_file, "-z", "endpoints,udp"]
            )["stdout"],
        }

    def _field_query(
        self, pcap_file: str, display_filter: str, fields: list[str]
    ) -> str:
        argv = [TSHARK, "-r", pcap_file, "-Y", display_filter, "-T", "fields"]
        for field in fields:
            argv += ["-e", field]
        return self._run(argv)["stdout"]

    def extract_credentials(self, pcap_file: str) -> dict[str, Any]:
        """Extract cleartext credentials from common protocols."""
        base = ("frame.time", "ip.src", "ip.dst")
        return {
            "http_basic": self._field_query(
                pcap_file, "http.authbasic", [*base, "http.authbasic"]
            ),
            "ftp": self._field_query(
                pcap_file,
                "ftp.request.command == USER || ftp.request.command == PASS",
                ["frame.time", "ip.src", "ftp.request.command", "ftp.request.arg"],
            ),
            "telnet": self._field_query(
                pcap_file, "telnet.data", ["frame.time", "ip.src", "telnet.data"]
            ),
            "smtp": self._field_query(
                pcap_file, "smtp.auth", ["frame.time", "ip.src", "smtp.auth"]
            ),
            "snmp": self._field_query(
                pcap_file, "snmp.community", ["frame.time", "ip.src", "snmp.community"]
            ),
        }

    def extract_files(
        self,
        pcap_file: str,
        output_dir: str,
        protocols: list[str] | None = None,
    ) -> dict[str, Any]:
        """Export transferred objects (HTTP/FTP/SMB/TFTP) to disk."""
        results: dict[str, Any] = {}
        for proto in protocols or ["http", "ftp", "smb", "tftp"]:
            obj_dir = os.path.join(output_dir, f"{proto}_objects")
            os.makedirs(obj_dir, exist_ok=True)
            result = self._run(
                [TSHARK, "-r", pcap_file, "--export-objects", f"{proto},{obj_dir}"]
            )
            results[proto] = {"dir": obj_dir, "output": result["stdout"]}
        return results

    def pcap_stats(self, pcap_file: str) -> dict[str, Any]:
        return {"stats": self._run([CAPINFOS, "-a", pcap_file])["stdout"]}

    def merge_pcaps(self, input_pcaps: list[str], output_pcap: str) -> dict[str, Any]:
        return self._run([MERGE_CAP, "-w", output_pcap, *input_pcaps])

    def split_pcap(
        self, input_pcap: str, output_pattern: str, count: int = 1000
    ) -> dict[str, Any]:
        return self._run([EDITCAP, "-c", str(count), input_pcap, output_pattern])

    def detect_anomalies(self, pcap_file: str) -> dict[str, Any]:
        """Cheap heuristics: SYN scans, DNS tunneling, unusual ports, ICMP."""
        return {
            "syn_scans": self._field_query(
                pcap_file,
                "tcp.flags.syn == 1 and tcp.flags.ack == 0",
                ["ip.dst", "tcp.dstport"],
            ),
            "dns_tunneling": self._field_query(
                pcap_file,
                "dns.qry.name.len > 50",
                ["frame.time", "ip.src", "dns.qry.name"],
            ),
            "unusual_ports": self._field_query(
                pcap_file,
                "tcp.port > 1024 and not tcp.port in {3389 5900 8080 8443}",
                ["tcp.dstport"],
            ),
            "icmp": self._field_query(
                pcap_file, "icmp", ["ip.src", "icmp.type", "icmp.code"]
            ),
        }


class TsharkRunner:
    """High-level traffic analysis orchestration."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.tshark = TsharkService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def full_pcap_analysis(self, pcap_file: str) -> dict[str, Any]:
        """Complete pcap analysis for a CTF."""
        self.progress("analyzing pcap", 10)
        stats = self.tshark.pcap_stats(pcap_file)
        self.progress("extracting flows", 30)
        flows = self.tshark.extract_flows(pcap_file)
        self.progress("extracting credentials", 50)
        creds = self.tshark.extract_credentials(pcap_file)
        self.progress("detecting anomalies", 70)
        anomalies = self.tshark.detect_anomalies(pcap_file)
        self.progress("extracting files", 90)
        files = self.tshark.extract_files(
            pcap_file, "/tmp/extracted"
        )  # nosec B108 - scratch dir
        return {
            "file": pcap_file,
            "stats": stats["stats"],
            "flows": flows,
            "credentials": creds,
            "anomalies": anomalies,
            "extracted_files": files,
        }

    def live_capture_analysis(
        self, interface: str, duration: int = 60, filter: str | None = None
    ) -> dict[str, Any]:
        """Capture live traffic to a temp pcap, then analyze it."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            pcap = fh.name
        try:
            self.tshark.capture_live(interface, duration, filter, pcap)
            return self.full_pcap_analysis(pcap)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(pcap)


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data
