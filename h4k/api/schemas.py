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


class DeepAttackRequest(BaseModel):
    """Deeper, separately-opted-in toolkit sweep (brute force, web vuln, smb,
    dns) using classic non-Metasploit tools. Distinct from the scan flag."""

    target: str
    host: str | None = None  # specific host (defaults to target address)
    services: list[str] = []  # ssh/http/smb/dns/...
    mode: ScanMode = ScanMode.overt


class ToolkitResult(BaseModel):
    tool: str
    host: str
    service: str = ""
    stdout: str = ""
    stderr: str = ""
    rc: int = 0


class AttackRequest(BaseModel):
    target: str
    mode: ScanMode = ScanMode.overt
    host: str | None = None  # specific host to attack, else all
    services: list[str] = []  # services to attack (ssh/http/smb/...)
    open_sessions: bool = False


class FuzzRequest(BaseModel):
    """LAB-ONLY: mutate inputs to a service you OWN to surface bug candidates."""

    target: str
    host: str | None = None  # default = target address
    service: str = "http"  # currently http vector
    port: int | None = None  # default 80/443 by scheme
    scheme: str = "http"
    iterations: int = 1
    timeout: float = 3.0


class VulnLeadsRequest(BaseModel):
    """Scan discovered services for outdated/EOL/beta version leads."""

    target: str


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


class SecurityAssessment(BaseModel):
    """Educated, traceroute-derived guess at the security posture of a host."""

    host: str
    level: str  # high | medium | low | unknown
    score: float  # 0-100 (higher = more exposed/better target)
    signals: list[str] = []
    rationale: list[str] = []
    confidence: str = "low"  # low | medium | high


class VersionLead(BaseModel):
    """A 'likely-unpatched / EOL / unusual build' lead from a service banner."""

    host: str
    service: str
    version: str
    product: str
    level: str  # eol | old | beta | unusual | unknown
    reason: str
    cve_link: str | None = None


class FuzzCandidate(BaseModel):
    """A potential bug candidate from lab fuzzing (for responsible disclosure)."""

    host: str
    service: str
    vector: str  # e.g. "GET /", "POST /login", "HTTP header X-Foo"
    signal: str  # teardown | server_error | hang | resource | anomaly
    repro: str  # the exact mutated request to reproduce
    evidence: str = ""  # response tail / error text
    severity: str = "low"  # low | medium | high
    note: str = ""


class FuzzResult(BaseModel):
    host: str
    service: str
    port: int | None = None
    vector: str
    signal: str
    repro: str
    evidence: str = ""
    payload_mutated: bool = True


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
    security: list[SecurityAssessment] = []
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


class SourceScanRequest(BaseModel):
    """Analyze a software project for vulnerabilities. One of:
    `git_url` to clone, or an uploaded archive (multipart file)."""

    git_url: str | None = None
    name: str = "source"


class SourceFinding(BaseModel):
    rule_id: str
    name: str
    severity: str  # low | medium | high | critical
    cwe: str
    file: str
    line: int
    code: str = ""
    description: str = ""


class SourceScanResult(BaseModel):
    name: str
    root: str = ""
    files_scanned: int = 0
    findings: list[SourceFinding] = []


class SourceExploitRequest(BaseModel):
    """Generate a proof-of-concept skeleton for a finding (disclosure only)."""

    rule_id: str
    finding: SourceFinding | None = None


class ScaResult(BaseModel):
    cves: list[str] = []
    vulnerabilities: list[dict] = []
    packages: list[str] = []
    sbom_available: bool = False


class TriageRequest(BaseModel):
    """Analyze a fuzzer crash candidate or SAST finding into a triage."""

    candidate: str = ""
    finding: SourceFinding | None = None


class TriageResult(BaseModel):
    candidate: str
    bug_class: str
    cwe: str
    minimized_trigger: str
    suggested_patch: str
    steps: list[str] = []


class AiRequest(BaseModel):
    """Ask the configured LLM for root-cause + patch-candidate on this input."""

    text: str


class AiResult(BaseModel):
    ok: bool
    provider: str = ""
    raw: str = ""
    error: str | None = None


class CustomRuleRequest(BaseModel):
    """Author & test a custom Semgrep-style rule."""

    rule_id: str
    name: str
    severity: str = "medium"  # low | medium | high | critical
    languages: list[str] = ["python"]
    pattern: str
    message: str = ""
    test_code: str = ""  # sample code to validate the rule against
