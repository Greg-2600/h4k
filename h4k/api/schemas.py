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


class Job(BaseModel):
    id: str
    status: str  # queued | running | done | error
    progress: float = 0.0
    message: str = ""
    report: Report | None = None
    error: str | None = None
