# h4k services package
from .ad_tools import ADToolsService, bloodhound_collect, mitm6_attack, responder_attack
from .ai import (
    _chat_endpoint,
    _model,
    _olla_base,
    _probe_ollama,
    _provider,
    ai_analyze,
    ollama_models,
)
from .ai_loop import ai_full_loop
from .aircrack import AircrackRunner, AircrackService
from .attack import AttackService
from .container_escape import ContainerEscape
from .crashes import CrashRegistry
from .creds import CredArchive
from .cve_lookup import CveDb
from .db_interrogate import DBInterrogate
from .discovery import NeighborFinder
from .engagement import EngagementStore
from .fuzzer import LabFuzzer
from .ingest import (
    IngestError,
    clone_git,
    extract_archive,
    find_source_root,
    is_archive,
    make_workdir,
    normalize_source_name,
)
from .john import JohnRunner, JohnService
from .lateral import LateralMovement
from .merged_report import build_merged_report
from .modes import MODES, TOR_SOCKS, ScanModeConfig, get_mode, scanners_for_service
from .msfrpc import MsfClient
from .nuclei import NucleiRunner, NucleiService, nuclei_scan
from .ossfuzz import OssFuzzRunner
from .propagate import PropagationService as CredentialPropagator
from .report import build_report
from .rules import delete_rule, list_rules, run_rule_via_regex, save_rule
from .sanitizer import (
    classify_trace,
    confirm_plan,
    flags,
    replay_command,
    trace_env,
    verify_plan,
)
from .sast import SASTScanner as sast_scan
from .sbom import build_supply_chain_map
from .sca import generate_sbom as build_sbom, sca_scan, scan_licenses, scan_secrets
from .scan_pipeline import ScanPipeline
from .security import SecurityAssessmentService
from .semgrep import scan_semgrep as semgrep_scan, test_rule
from .sniffer import (
    arp_who,
    detect_interfaces,
    mitm_arp_poison,
    sniff_packets,
    wifi_capture,
    wifi_scan,
)
from .sqlmap import SQLMapRunner, SQLMapService, sqlmap_scan
from .tls_lab import install_ca_to_trust, setup_ca, start_https_proxy, status
from .toolkit import ToolkitPlan, ToolkitRunner
from .triage import TriageReport as TriageEngine
from .tshark import TsharkRunner, TsharkService
from .updater import refresh_cve_data, refresh_tools, run_update, should_run
from .vulnleads import analyze_service
from .zap import ZAPRunner, ZAPService, zap_scan

__all__ = [
    "MODES",
    "TOR_SOCKS",
    "ADToolsService",
    "AircrackRunner",
    "AircrackService",
    "AttackService",
    "ContainerEscape",
    "CrashRegistry",
    "CredArchive",
    "CredentialPropagator",
    "CveDb",
    "DBInterrogate",
    "EngagementStore",
    "IngestError",
    "JohnRunner",
    "JohnService",
    "LabFuzzer",
    "LateralMovement",
    "MsfClient",
    "NeighborFinder",
    "NucleiRunner",
    "NucleiService",
    "OssFuzzRunner",
    "SQLMapRunner",
    "SQLMapService",
    "ScanModeConfig",
    "ScanPipeline",
    "SecurityAssessmentService",
    "ToolkitPlan",
    "ToolkitRunner",
    "TriageEngine",
    "TsharkRunner",
    "TsharkService",
    "ZAPRunner",
    "ZAPService",
    "_chat_endpoint",
    "_model",
    "_olla_base",
    "_probe_ollama",
    "_provider",
    "ai_analyze",
    "ai_full_loop",
    "analyze_service",
    "arp_who",
    "bloodhound_collect",
    "build_merged_report",
    "build_report",
    "build_sbom",
    "build_supply_chain_map",
    "classify_trace",
    "clone_git",
    "confirm_plan",
    "delete_rule",
    "detect_interfaces",
    "extract_archive",
    "find_source_root",
    "flags",
    "get_mode",
    "install_ca_to_trust",
    "is_archive",
    "list_rules",
    "make_workdir",
    "mitm6_attack",
    "mitm_arp_poison",
    "normalize_source_name",
    "nuclei_scan",
    "ollama_models",
    "refresh_cve_data",
    "refresh_tools",
    "replay_command",
    "responder_attack",
    "run_rule_via_regex",
    "run_update",
    "sast_scan",
    "save_rule",
    "sca_scan",
    "scan_licenses",
    "scan_secrets",
    "scanners_for_service",
    "semgrep_scan",
    "setup_ca",
    "should_run",
    "sniff_packets",
    "sqlmap_scan",
    "start_https_proxy",
    "status",
    "test_rule",
    "trace_env",
    "verify_plan",
    "wifi_capture",
    "wifi_scan",
    "zap_scan",
]
