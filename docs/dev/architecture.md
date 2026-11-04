# Architecture

How h4k is put together, and why.

```
┌──────────────────────────────────────────────────────────────────────┐
│ browser                                                               │
│  web/index.html + app.js + style.css                                  │
│  6 phases: Discover · Recon · Exploit · Pivot · Persist · Score      │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ HTTP/JSON :3137
┌───────────────────────────────▼──────────────────────────────────────┐
│ FastAPI (h4k/api)                                                    │
│  main.py        app, lifespan, rate limiting, static mount            │
│  routers/       scan · source · update · net · engagement            │
│  services/      ~65 modules: pipeline, recon, exploit,               │
│                 SCA, fuzzing, AI, Fire TV, container-fuzz …          │
└───────┬───────────────────────────────┬───────────────────────────────┘
        │ RPC                          │ subprocess
┌───────▼────────┐          ┌───────────▼────────────────────────────┐
│ Metasploit     │          │ offensive + analysis tools              │
│ msfrpcd :55553 │          │ nmap · hydra · nikto · sqlmap · semgrep │
│ + PostgreSQL   │          │ trivy · osv-scanner · gobuster · …      │
└────────────────┘          └────────────────────────────────────────┘
```

## The layers

### Routers (`h4k/api/routers/`)

HTTP shape only: parse the request, call services, return JSON. No business
logic lives here.

| Router | Responsibility |
|---|---|
| `scan.py` | Recon, jobs, attacks, autopilot, neighbors, toolkit, CTF endpoints |
| `source.py` | SAST, SCA, SBOM, fuzzing, triage, AI, rules, reports |
| `engagement.py` | Engagements, scope, assets, credentials, crown jewels, attack paths, ATT&CK |
| `update.py` | Tool/CVE/rule refresh status |
| `net.py` | interfaces, sniff/ARP/MITM/WiFi, TLS lab, auto-scan map |

### Services (`h4k/api/services/`)

The actual work. Two rules:

* **No HTTP concepts.** A service takes plain data and returns plain data.
* **Testable seams.** Anything that shells out is isolated behind one
  function so tests can substitute it (see `ToolkitRunner.run_tool`,
  `MsfClient.execute`).

| module | purpose |
|---|---|
| `scan_pipeline.py` | orchestrator: recon → fingerprint → scan → creds → attack |
| `modes.py` | stealth / tor / overt configuration |
| `cve_lookup.py` | offline curated CVE matcher (banner-aware) |
| `creds.py` | default-credential archive matching |
| `attack.py` | opt-in Metasploit exploit execution with option validation |
| `toolkit.py` | opt-in non-Metasploit tools (hydra/nikto/sqlmap/…) |
| `discovery.py` | ARP / IPv6 / SNMP neighbour discovery |
| `engagement.py` | scope-enforced persistent engagement store (SQLite) |
| `propagate.py` | replay of *verified* credentials across the estate |
| `attack_paths.py` | crown jewels → scored, evidence-backed paths |
| `attck.py` | ATT&CK technique mapping + defender detection guidance |
| `sandbox.py` | deterministic stand-ins for nmap/hydra/Metasploit |
| `fuzzer.py` / `crashes.py` / `triage.py` | fuzzing, dedup, triage |
| `sast.py` / `semgrep.py` / `sca.py` | source analysis |
| `ai.py` / `ai_loop.py` | local or OpenAI-compatible LLM assistance |

### Data stores

| Store | Contents | Location |
|---|---|---|
| `neighbors.db` | session hosts, services, vulns, creds, sessions, autopilot runs | `H4K_DATA_DIR` (default `/opt/h4k/data`, else `h4k/data`) |
| `engagements.db` | engagements, assets, services, credentials, access, vulns, attempts, crown jewels | same directory |
| `cves.json`, `creds.json` | curated offline archives | `h4k/data/` |
| `users.txt`, `passwords.txt`, `web-words.txt` | wordlists | `h4k/data/` |

`H4K_DATA_DIR` overrides the runtime directory — that is how the test suite
and the Selenium run get an isolated, disposable data directory.

### Data flow of a scan

```
POST /api/scan
  → ScanRequest validated (pydantic)
  → mode/depth resolved (modes.py)
  → job registered (JOBS)
  → pipeline thread:
       discovery (ARP/MSF)  → neighbours
       fingerprint (nmap -sS -sV -O) → services, banners, OS guess
       CVE match (cve_lookup)  → findings
       [opt-in] default creds (creds.py + msf/tk)
       [opt-in] exploits (attack.py)
  → Report assembled (report.py)
  → cached (300 s TTL) and returned as {job_id, status}
```

## Key design decisions

1. **Metasploit over RPC**, not `msfconsole -x` — structured data, job ids.
2. **Aggressive actions are opt-in** and off by default.
3. **Scope is enforced in the store**, not the UI.
4. **Propagation only replays verified credentials** and keeps a ledger.
5. **Depth and OPSEC mode are separate axes**; partial sweeps are labelled.
6. **Curated offline CVE/cred archives** — banner-aware, refreshable.
7. **SBOM/SCA is honest** — no lockfile, no claims.
8. **PoCs are disclosure skeletons**, not weapons.
9. **Local-first AI** (Ollama/opencode relay), no key required.
10. **Sandbox mode** replaces only the tool leaves, so the whole pipeline can
    be exercised deterministically (demo + CI + Selenium).

## Threading model

* FastAPI endpoints are sync or async; long work runs in a **thread**
  (`threading.Thread(..., daemon=True)`) and is tracked in a job registry
  (`JOBS`, `_attack_jobs`, `_toolkit_jobs`, `_fuzz_jobs`, plus
  `_neighbor_jobs`, `_fingerprint_jobs`, `_passattack_jobs`,
  `_cfuzz_jobs`). `GET /api/jobs` merges every family; every runner flips
  `queued` → `running` up front so the monitor never sticks on queued.
* Job state is plain dicts mutated under the GIL; SQLite writes are
  serialized by a lock inside `EngagementStore`.
* The rate limiter is an in-memory per-IP sliding window (600 req/min).
