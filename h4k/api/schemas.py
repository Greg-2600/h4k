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
    # an operator triaging a specific finding can name the module and port
    # instead of letting the service->module heuristic choose; both optional.
    module: str | None = None
    port: int | None = None
    # Module-specific options (e.g. USER_FILE for ssh_brute, URI for an HTTP
    # exploit). Only options the chosen module actually declares are passed
    # through, so this cannot smuggle arbitrary settings into Metasploit.
    options: dict[str, Any] = {}
    # Check-only dry run: run the module's `check` (version/cred probing,
    # no exploitation) and report vulnerable/safe/unknown. Used to confirm
    # a finding before firing.
    check_only: bool = False


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
    version: str | None = None
    product: str | None = None
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
    progress: float | None = None
    message: str = ""
    report: Report | None = None
    error: str | None = None
    cached: bool = False
    # Without these, response_model filtering drops them and the UI's
    # incremental log tail is dead code.
    log: list[str] = []
    created: str | None = None
    updated: str | None = None
    # so a client that holds only a job id can still say what it is scanning
    target: str | None = None
    # job family type injected by _job_summary for the monitor
    type: str | None = None


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
    max_per_user: int = 25
    jitter_max: float = 0.0


# ---- CTF / lab toolkit schemas -------------------------------------------
# These wrap the opt-in tools (ZAP, John, aircrack, tshark, NSE, container
# escape, lateral, DB interrogation). They run only when explicitly called.


class ZapRequest(BaseModel):
    """OWASP ZAP web application scan request."""

    target: str  # URL to scan
    mode: str = "full"  # full | spider | active


class ZapResult(BaseModel):
    target: str = ""
    alerts: list[dict[str, Any]] = []
    alert_count: int = 0
    high_risk: list[dict[str, Any]] = []
    medium_risk: list[dict[str, Any]] = []
    report_html: str = ""


class JohnRequest(BaseModel):
    """John the Ripper hash cracking request."""

    hashes: list[str] | str  # hash or list of hashes
    formats: list[str] | None = None  # auto-detect if None
    wordlist: str | None = None
    max_time_per_format: int = Field(default=60, ge=1, le=36_000)


class JohnResult(BaseModel):
    total: int = 0
    cracked: list[dict[str, Any]] = []
    by_format: dict[str, list[dict[str, Any]]] = {}
    formats_tried: list[str] = []
    remaining: list[str] = []


class AircrackRequest(BaseModel):
    """Aircrack-ng wireless assessment request."""

    interface: str  # wireless interface (put into monitor mode)
    target_essid: str | None = None  # specific ESSID to target
    wordlist: str | None = None
    capture_duration: int = 60  # handshake capture duration


class AircrackResult(BaseModel):
    interface: str = ""
    networks: list[dict[str, Any]] = []
    handshakes: list[dict[str, Any]] = []
    error: str | None = None


class TsharkRequest(BaseModel):
    """Tshark packet capture/analysis request (one of pcap_file/interface)."""

    pcap_file: str | None = None  # existing pcap to analyze
    interface: str | None = None  # live capture interface
    duration: int = 60  # live capture duration
    filter: str | None = None  # capture/display filter


class TsharkResult(BaseModel):
    file: str = ""
    stats: str = ""
    flows: dict[str, Any] = {}
    credentials: dict[str, Any] = {}
    anomalies: dict[str, Any] = {}
    extracted_files: dict[str, Any] = {}


class NmapNSERequest(BaseModel):
    """Enhanced Nmap with NSE scripts."""

    target: str
    scripts: str = "vuln,auth,default"  # NSE script categories
    timing: str = "T4"
    ports: str | None = None  # e.g., "1-1000" or "22,80,443"


class NmapNSEResult(BaseModel):
    target: str
    tool: dict[str, Any] = {}


class TlsFingerprintRequest(BaseModel):
    """Active TLS fingerprint of one host you own (opt-in)."""

    target: str
    ports: list[int] | None = None  # defaults to 443/8443/9443
    timeout: float = Field(default=10.0, gt=0, le=60.0)
    watchlist: list[str] | None = None  # known-bad fingerprints (exact match)


class TlsFingerprintResult(BaseModel):
    host: str = ""
    ports: list[int] = []
    probes: list[dict[str, Any]] = []
    fingerprints: list[str] = []
    lead_count: int = 0
    sandbox: bool = False


class TlsInventoryRequest(BaseModel):
    """TLS cert inventory over host[:port] targets you own (opt-in)."""

    targets: list[str] = []
    timeout: float = Field(default=10.0, gt=0, le=60.0)
    watchlist: list[str] | None = None  # known-bad fingerprints (exact match)
    engagement_id: str | None = None  # ledger expiry/weak/self-signed leads


class TlsInventoryResult(BaseModel):
    targets: list[str] = []
    entries: list[dict[str, Any]] = []
    count: int = 0
    lead_count: int = 0
    fingerprints: list[str] = []
    ingested: int = 0
    skipped_out_of_scope: list[str] = []
    sandbox: bool = False


class KerberosRoastRequest(BaseModel):
    """AS-REP / Kerberos roast request (explicit, opt-in)."""

    domain: str
    dc_ip: str | None = None
    users: list[str] | None = None  # asrep: accounts to request
    user: str | None = None  # kerberoast: one valid account
    password: str | None = None
    crack: bool = False  # hand hashes to John (explicit second step)
    wordlist: str | None = None
    max_time: int = Field(default=60, ge=1, le=3600)


class KerberosRoastResult(BaseModel):
    kind: str = ""
    hashes: list[str] = []
    hash_count: int = 0
    cracked: list[dict[str, Any]] = []
    stdout: str = ""
    stderr: str = ""
    rc: int | None = None
    success: bool = False
    timed_out: bool = False


class NiktoRequest(BaseModel):
    """Standalone nikto web vulnerability scan."""

    target: str  # URL or host to scan
    maxtime: int = 120  # per-host budget in seconds
    tuning: str | None = None  # nikto -Tuning value, e.g. "x"


class NiktoResult(BaseModel):
    target: str
    tool: dict[str, Any] = {}


class GobusterRequest(BaseModel):
    """Standalone gobuster content discovery."""

    target: str  # base URL
    wordlist: str | None = None  # defaults to the bundled common list
    mode: str = "dir"  # dir | dns | vhost | fuzz
    threads: int = 10
    extensions: str | None = None  # e.g. "php,html"


class GobusterResult(BaseModel):
    target: str
    tool: dict[str, Any] = {}


class ContainerEscapeResult(BaseModel):
    capabilities: list[str] = []
    dangerous_caps: list[str] = []
    mounts: list[str] = []
    dangerous_mounts: list[str] = []
    cgroup_path: str = ""
    is_privileged: bool = False
    vectors: list[dict[str, Any]] = []


class LateralRequest(BaseModel):
    cidr: str = "192.168.1.0/24"


class DBInterrogateRequest(BaseModel):
    target: str = "127.0.0.1"


class FireTVRequest(BaseModel):
    """Fire TV / Android TV assessment request (one target, one action)."""

    target: str = ""  # IP or hostname of the TV (empty for mdns/ssdp sweeps)
    port: int = 5555  # ADB port
    command: str | None = None  # shell: command string
    key: str | None = None  # keyevent: KEYCODE name or 0-255
    code: str | None = None  # pair: 6-digit on-screen pairing code
    remote: str | None = None  # pull: remote path on the TV
    local: str | None = None  # pull: local name / install: local APK path
    lines: int = 200  # logcat: recent line count
    queries: list[str] | None = None  # mdns: service types to ask for


class FireTVResult(BaseModel):
    target: str = ""
    action: str = ""
    success: bool = False
    output: str = ""
    detail: dict[str, Any] = {}
    error: str | None = None


# ---- Nuclei ----
class NucleiRequest(BaseModel):
    """Nuclei template-based vulnerability scan request (opt-in)."""

    target: str
    templates: list[str] | None = None
    severity: str | None = None
    # offline=True runs only the bundled templates (no network fetch).
    offline: bool = False
    # engagement_id opts into the ledger: findings are recorded as vulns
    # in that engagement (scope-enforced, out-of-scope hosts skipped).
    engagement_id: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class NucleiResult(BaseModel):
    target: str = ""
    findings: list[dict[str, Any]] = []
    finding_count: int = 0
    stdout: str = ""
    stderr: str = ""
    rc: int | None = None
    success: bool = False
    timed_out: bool = False
    offline: bool = False
    ingested: int = 0
    skipped_out_of_scope: list[str] = []


# ---- SQLMap ----
class SqlmapRequest(BaseModel):
    """SQLMap automated SQL injection scan request."""

    url: str
    options: dict[str, Any] = Field(default_factory=dict)


class SqlmapResult(BaseModel):
    url: str = ""
    findings: list[dict[str, Any]] = []
    stdout: str = ""
    stderr: str = ""
    rc: int | None = None
    success: bool = False
    timed_out: bool = False


# ---- AD Tools ----
class ADBloodhoundRequest(BaseModel):
    domain: str
    username: str
    password: str
    options: dict[str, Any] = Field(default_factory=dict)


class ADMitm6Request(BaseModel):
    interface: str
    options: dict[str, Any] = Field(default_factory=dict)


class ADResponderRequest(BaseModel):
    interface: str
    options: dict[str, Any] = Field(default_factory=dict)


# ---- Ollama Exploit ----


class OllamaResult(BaseModel):
    """Result from Ollama exploit/discover operations."""

    ollama_detected: bool = False
    auth_bypass: bool = False
    tool_calling_available: bool = False
    models: list[dict[str, Any]] = Field(default_factory=list)
    dangerous_capabilities: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None


class OllamaRceResult(BaseModel):
    """Result from Ollama tool-calling RCE execution."""

    target: str
    port: int
    command: str
    stdout: str = ""
    stderr: str = ""
    rc: int = 0
    error: str | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)


# ---- API improvements ----


class PaginatedJobs(BaseModel):
    """Paginated job list response."""

    jobs: list[Job]
    total: int
    active: int
    page: int
    per_page: int
    pages: int


class BatchScanRequest(BaseModel):
    """Scan multiple targets in one call."""

    targets: list[str]
    mode: ScanMode = ScanMode.overt
    depth: ScanDepth = ScanDepth.standard
    do_dns_recon: bool = False
    do_vuln_scan: bool = True
    try_default_creds: bool = False
    open_sessions: bool = False
    do_attack: bool = False


class BatchScanResult(BaseModel):
    """Result of a batch scan launch."""

    batch_id: str
    jobs: list[Job]
    launched: int
    message: str


class StreamEvent(BaseModel):
    """Server-Sent Event payload for job log streaming."""

    event: str  # "log" | "progress" | "status" | "complete"
    job_id: str
    data: dict[str, Any]


class HealthDetail(BaseModel):
    """Detailed health with component status."""

    status: str
    msf: dict[str, Any]
    jobs: dict[str, Any]
    cache_entries: int
    updater: str
    version: str


class ContainerFuzzRequest(BaseModel):
    """LAB-ONLY: mutate inputs to container surfaces you OWN.

    surface docker = local Engine API over the unix socket; kubelet =
    TLS API on target:10250; grpc = containerd framing over its socket;
    http = generic endpoint list (CAD-worker style). Read-only GET
    endpoints unless allow_mutating opts into POST shapes.
    """

    surface: str = "docker"  # docker | kubelet | grpc | http
    target: str = "127.0.0.1"
    port: int | None = None  # preset default when omitted
    endpoints: list[str] | None = None  # override the preset endpoint list
    iterations: int = Field(default=200, ge=1, le=20_000)
    timeout: float = Field(default=3.0, gt=0, le=10.0)
    seed: int | None = None
    allow_mutating: bool = False  # include POST endpoint shapes


class ContainerFuzzResult(BaseModel):
    job_id: str = ""
    status: str = ""
