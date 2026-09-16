# h4k API schemas
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class ScanMode(StrEnum):
    stealth = "stealth"
    tor = "tor"
    overt = "overt"


class ScanRequest(BaseModel):
    target: str  # IP, domain, or CIDR
    mode: ScanMode = ScanMode.overt
    do_dns_recon: bool = True
    do_vuln_scan: bool = True
    # OPT-IN only: attempt default/known credentials against fingerprinted
    # services. Off by default. When enabled, `open_sessions` controls whether
    # a successful login opens an interactive session (default: verify only).
    try_default_creds: bool = False
    open_sessions: bool = False
    # OPT-IN: after scanning, attempt active exploitation (metasploit exploits)
    # against discovered services. Defaults off.
    do_attack: bool = False


class AttackRequest(BaseModel):
    target: str
    mode: ScanMode = ScanMode.overt
    host: str | None = None  # specific host to attack, else all
    services: list[str] = []  # services to attack (ssh/http/smb/...)
    open_sessions: bool = False


class Service(BaseModel):
    port: int
    proto: str = "tcp"
    service: str | None = None
    state: str | None = None
    info: str | None = None


class Host(BaseModel):
    address: str
    hostname: str | None = None
    os: str | None = None
    state: str | None = None
    services: list[Service] = []


class Vuln(BaseModel):
    name: str
    refs: list[str] = []
    port: int | None = None
    info: str | None = None


class Recommendation(BaseModel):
    rank: int
    title: str
    module: str | None = None
    why: str
    difficulty: str
    refs: list[str] = []


class Credential(BaseModel):
    vendor: str = "common"
    service: str
    host: str
    port: int | None = None
    user: str
    password: str
    module: str | None = None
    verified: bool = False
    note: str | None = None


class Fingerprint(BaseModel):
    host: str
    vendor: str | None = None
    model: str | None = None
    os: str | None = None
    technology: list[str] = []
    source: list[str] = []


class Attack(BaseModel):
    host: str
    service: str
    port: int | None = None
    module: str
    result: str  # success | failed | skipped | error
    detail: str = ""
    session_id: int | None = None
    credential: str | None = None


class Report(BaseModel):
    target: str
    mode: ScanMode
    created_at: str
    hosts: list[Host] = []
    vulns: list[Vuln] = []
    recommendations: list[Recommendation] = []
    notes: list[str] = []
    raw: dict[str, Any] | None = None
    fingerprints: list[Fingerprint] = []
    credentials: list[Credential] = []
    attacks: list[Attack] = []
    log: list[str] = []


class Job(BaseModel):
    id: str
    status: str  # queued | running | done | error | aborted
    progress: float = 0.0
    message: str = ""
    report: Report | None = None
    error: str | None = None
    cached: bool = False


class Neighbor(BaseModel):
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None


class ScanSummary(BaseModel):
    target: str
    mode: ScanMode
    status: str
    created_at: str
    cached: bool = False


class ExportResult(BaseModel):
    job_id: str
    formats: list[str] = []
    filenames: dict[str, str] = {}
