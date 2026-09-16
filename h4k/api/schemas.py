# h4k API schemas
from enum import Enum
from typing import Any, List, Optional, Dict

from pydantic import BaseModel


class ScanMode(str, Enum):
    stealth = "stealth"
    tor = "tor"
    overt = "overt"


class ScanRequest(BaseModel):
    target: str  # IP, domain, or CIDR
    mode: ScanMode = ScanMode.overt
    do_dns_recon: bool = True
    do_vuln_scan: bool = True


class Service(BaseModel):
    port: int
    proto: str = "tcp"
    service: Optional[str] = None
    state: Optional[str] = None
    info: Optional[str] = None


class Host(BaseModel):
    address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    state: Optional[str] = None
    services: List[Service] = []


class Vuln(BaseModel):
    name: str
    refs: List[str] = []
    port: Optional[int] = None
    info: Optional[str] = None


class Recommendation(BaseModel):
    rank: int
    title: str
    module: Optional[str] = None
    why: str
    difficulty: str
    refs: List[str] = []


class Report(BaseModel):
    target: str
    mode: ScanMode
    created_at: str
    hosts: List[Host] = []
    vulns: List[Vuln] = []
    recommendations: List[Recommendation] = []
    notes: List[str] = []
    raw: Optional[Dict[str, Any]] = None


class Job(BaseModel):
    id: str
    status: str  # queued | running | done | error
    progress: float = 0.0
    message: str = ""
    report: Optional[Report] = None
    error: Optional[str] = None
