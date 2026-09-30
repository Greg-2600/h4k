# h4k API schemas
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanMode(StrEnum):
    stealth = "stealth"
    tor = "tor"
    overt = "overt"


class ScanDepth(StrEnum):
    """Port breadth. Separate from ScanMode, which controls *how* we probe.

    Only `full` enumerates all 65535 TCP ports; quick/standard are partial
    sweeps and are reported as such (`Coverage.complete` is false).
    """

    quick = "quick"  # top 100
    standard = "standard"  # top 1000
    full = "full"  # 1-65535


class Coverage(BaseModel):
    """What the port scan actually enumerated. Attached to every report so a
    partial sweep is never presented as a complete one."""

    depth: str = "standard"
    ports_spec: str = "top-1000"
    max_ports: int = 1000
    complete: bool = False


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
    # Port breadth, independent of `mode`. Anything but "full" is a PARTIAL
    # sweep and the report will carry coverage.complete=false.
    depth: ScanDepth = ScanDepth.standard


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
    rc: int | None = None
    elapsed: float = 0.0
    # A timed-out tool keeps its partial output: a brute force that found a
    # hit before the deadline must not have the hit thrown away.
    timed_out: bool = False
    status: str = "ok"  # ok | timeout | missing | error


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
    # Bounded on purpose: an unbounded iteration count is a self-inflicted
    # DoS against the operator's own target (and this API's worker). The
    # ceiling is generous but finite.
    iterations: int = Field(default=200, ge=1, le=200_000)
    timeout: float = Field(default=3.0, gt=0, le=60.0)


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
    sanitizer: dict[str, Any] = {}  # replay recipe + plausible bug classes


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
    coverage: Coverage | None = None


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
    sanitizer: dict[str, Any] = {}  # flags + expected trace to confirm/refute


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
    secrets: list[dict] = []
    licenses: list[dict] = []


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
    # True only when the trigger was genuinely reduced; otherwise
    # minimized_trigger is the untouched candidate and minimize_note says why.
    minimized: bool = False
    minimize_note: str = ""


class AiRequest(BaseModel):
    """Ask the configured LLM for root-cause + patch-candidate on this input."""

    text: str
    model: str | None = None  # optional Ollama model override


class AiResult(BaseModel):
    ok: bool
    provider: str = ""
    raw: str = ""
    error: str | None = None


class AiLoopResult(BaseModel):
    ok: bool
    provider: str = ""
    raw: str = ""
    error: str | None = None
    parsed: dict[str, str] = {}


class CustomRuleRequest(BaseModel):
    """Author & test a custom Semgrep-style rule."""

    rule_id: str
    name: str
    severity: str = "medium"  # low | medium | high | critical
    languages: list[str] = ["python"]
    pattern: str
    message: str = ""
    cwe: str = "CWE-710"
    test_code: str = ""  # sample code to validate the rule against


class EngagementRequest(BaseModel):
    """Create an engagement. `scope` is the authorized IP/CIDR list and is
    enforced on every write and every replayed login attempt — it is the
    boundary, not a label."""

    name: str
    scope: list[str]
    notes: str = ""


class PropagateRequest(BaseModel):
    """OPT-IN: replay credentials already verified in this engagement against
    other in-scope services. Off by default; never invents new candidates."""

    open_sessions: bool = False
    max_attempts: int = 500


class ZapRequest(BaseModel):
    """OWASP ZAP web application scan request."""

    target: str  # URL to scan
    mode: str = "full"  # full | spider | active
    authenticated: bool = False
    credentials: dict | None = None  # {username, password, login_url, ...}


class ZapResult(BaseModel):
    target: str
    alerts: list[dict] = []
    alert_count: int = 0
    high_risk: list[dict] = []
    medium_risk: list[dict] = []
    report_html: str = ""


class JohnRequest(BaseModel):
    """John the Ripper hash cracking request."""

    hashes: list[str] | str  # hash or list of hashes
    format: str | None = None  # hash format (md5, sha256, nt, etc.)
    wordlist: str | None = None
    rules: str = "single"  # single | wordlist | Jumbo | NTLM
    session: str | None = None
    max_time: int = 3600


class JohnResult(BaseModel):
    cracked: list[dict] = []
    total: int = 0
    by_format: dict = {}
    status: dict = {}


class AircrackRequest(BaseModel):
    """Aircrack-ng wireless assessment request."""

    interface: str  # wireless interface (will be put in monitor mode)
    target_essid: str | None = None  # specific ESSID to target
    wordlist: str | None = None
    duration: int = 30  # scan duration
    capture_duration: int = 60  # handshake capture duration


class AircrackResult(BaseModel):
    interface: str
    networks: list[dict] = []
    handshakes: list[dict] = []
    cracked: list[dict] = []


class TsharkRequest(BaseModel):
    """Tshark packet capture/analysis request."""

    pcap_file: str | None = None  # existing pcap to analyze
    interface: str | None = None  # live capture interface
    duration: int = 60  # live capture duration
    filter: str | None = None  # capture/display filter


class TsharkResult(BaseModel):
    stats: str = ""
    flows: dict = {}
    credentials: dict = {}
    anomalies: dict = {}
    extracted_files: dict = {}


class NmapNSERequest(BaseModel):
    """Enhanced Nmap with NSE scripts."""

    target: str
    scripts: str = "vuln,auth,default"  # NSE script categories
    timing: str = "T4"
    ports: str | None = None  # e.g., "1-1000" or "22,80,443"


class NmapNSEResult(BaseModel):
    target: str
    open_ports: list[dict] = []
    scripts_output: list[dict] = []


class ContainerEscapeResult(BaseModel):
    capabilities: list[str] = []
    dangerous_caps: list[str] = []
    mounts: list[str] = []
    dangerous_mounts: list[str] = []
    vectors: list[dict] = []
    is_privileged: bool = False


class LateralResult(BaseModel):
    cidr: str
    hosts: list[dict] = []
    routes: list[dict] = []
    services: dict = {}
    local_ips: list[str] = []


class DBInterrogateResult(BaseModel):
    target: str
    apis: dict = {}
    databases: dict = {}
    env_vars: dict = {}
    config_files: dict = {}
    flags: list[str] = []


class JohnHashes(BaseModel):
    """CTF hash cracking with multiple formats."""

    hashes: list[str] | str
    formats: list[str] | None = None  # auto-detect if None
    wordlist: str | None = None
    max_time_per_format: int = 300


class AircrackAssessment(BaseModel):
    interface: str
    target_essid: str | None = None
    wordlist: str | None = None


class TsharkPcapAnalysis(BaseModel):
    pcap_file: str
