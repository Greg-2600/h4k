# Default-credential archive: loads data/creds.json and returns candidate
# credentials matched by vendor fingerprint (make/model) plus the universal
# common list. Used opt-in against authorized lab targets.
import json
import logging
from pathlib import Path
from typing import Any

from schemas import Service

logger = logging.getLogger("h4k.creds")

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "creds.json"

# Discovered service -> Metasploit auxiliary login module
SERVICE_MODULES: dict[str, str] = {
    "http": "auxiliary/scanner/http/http_login",
    "https": "auxiliary/scanner/http/http_login",
    "ssh": "auxiliary/scanner/ssh/ssh_login",
    "telnet": "auxiliary/scanner/telnet/telnet_login",
    "smb": "auxiliary/scanner/smb/smb_login",
    "microsoft-ds": "auxiliary/scanner/smb/smb_login",
    "netbios-ssn": "auxiliary/scanner/smb/smb_login",
    "rdp": "auxiliary/scanner/rdp/rdp_login",
    "ms-wbt-server": "auxiliary/scanner/rdp/rdp_login",
    "mysql": "auxiliary/scanner/mysql/mysql_login",
    "mssql": "auxiliary/scanner/mssql/mssql_login",
    "ms-sql-s": "auxiliary/scanner/mssql/mssql_login",
    "postgres": "auxiliary/scanner/postgres/postgres_login",
    "postgresql": "auxiliary/scanner/postgres/postgres_login",
    "ftp": "auxiliary/scanner/ftp/ftp_login",
}


class CredArchive:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or DATA_FILE)
        self.universal: list[dict[str, Any]] = []
        self.vendors: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            logger.warning("credential data not found at %s", self.path)
            self.universal = []
            self.vendors = []
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.universal = data.get("universal", [])
            self.vendors = data.get("vendors", [])
            logger.info(
                "loaded credential archive: %d universal, %d vendors",
                len(self.universal),
                len(self.vendors),
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("failed to load credential archive: %s", exc)
            self.universal = []
            self.vendors = []

    # ---- fingerprint matching ----------------------------------------------

    def match_fingerprints(self, fingerprints: list[str]) -> list[dict[str, Any]]:
        """Return vendor cred entries whose vendor/fingerprint substrings match."""
        if not fingerprints:
            return []
        haystack = " ".join(fingerprints).lower()
        matched: list[dict[str, Any]] = []
        for vendor in self.vendors:
            fps = [str(f).lower() for f in vendor.get("fingerprints", [])]
            if any(f and f in haystack for f in fps):
                matched.extend(vendor.get("creds", []))
        return matched

    # ---- candidate enumeration ---------------------------------------------

    def universal_for_service(self, svc: Service) -> list[dict[str, Any]]:
        """Universal creds that apply to a concrete discovered service."""
        return [c for c in self.universal if _cred_matches_svc(c, svc.service)]

    def vendor_for_service(
        self, creds: list[dict[str, Any]], svc: Service
    ) -> list[dict[str, Any]]:
        """Vendor creds that apply to a concrete discovered service."""
        return [c for c in creds if _cred_matches_svc(c, svc.service)]

    def module_for_service(self, svc: Service) -> str | None:
        name = (svc.service or "").lower()
        for key in SERVICE_MODULES:
            if key in name:
                return SERVICE_MODULES[key]
        return None

    def as_meta(self) -> dict[str, Any]:
        return {
            "universal": len(self.universal),
            "vendors": len(self.vendors),
            "vendor_names": [v.get("vendor") for v in self.vendors],
        }


def _cred_matches_svc(cred: dict[str, Any], actual: str | None) -> bool:
    a = (actual or "").lower()
    for expected in cred.get("services", []):
        e = str(expected).lower()
        # exact/substring on the service name; "smb" also covers the
        # microsoft-ds / netbios-ssn names nmap reports for Windows shares.
        if e == "smb" and a in ("microsoft-ds", "netbios-ssn"):
            return True
        if e and (e in a or a in e):
            return True
    return False
