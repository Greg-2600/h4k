# h4k — session context for AI agents

This file gives an agent everything needed to work safely and correctly on this
repo. Read it before touching code.

## What this is

**h4k** is a self-contained, containerized **offensive-security analysis
platform** for a school capstone. It drives **Metasploit** over its RPC interface
and layers a modern analysis stack on top: coverage-guided fuzzing, static
analysis (Semgrep + heuristics), supply-chain/SBOM checking, an opt-in attack
toolkit, local-LLM (Ollama) root-cause/patching assistance, and responsible-
disclosure scaffolding.

> **Authorization is not optional.** Every aggressive action (cred testing,
> Metasploit exploits, deep toolkit, fuzzing, AI-assist) is **opt-in and off by
> default**. A plain scan only reconnoiters/advises. This is a lab tool for
> systems you own or have written permission to test.

## Repo layout (top level)

```
HACKING/                 git root
  .venv/                 local dev venv (host tooling only; NOT in the container)
  pyproject.toml         linter/test config (black/ruff/isort/flake8/mypy/pylint/bandit)
  Makefile               fmt / fix / lint / test / coverage
  requirements.txt       runtime deps
  requirements-dev.txt   lint+test toolchain
  RELEASE_NOTES.md       feature + design-decision inventory
  ROADMAP.md             prioritized future work
  AGENTS.md              (this file — read me first)
  h4k/                   the main platform image
    Dockerfile           debian12 + postgres + tor + metasploit + offensive tools + semgrep/osv/trivy
    docker-compose.yml   h4k + vulnlab + optional ollama-sidecar
    entrypoint.sh        boot: postgres -> msfdb -> tor -> msfrpcd -> uvicorn
    api/                 FastAPI app
      main.py            app + lifespan (starts periodic updater)
      schemas.py         all pydantic models
      routers/           scan.py, source.py, update.py
      services/          ~24 modules (see below)
    data/                cves.json, creds.json, wordlists, custom_rules.json (runtime)
    web/                 light dashboard UI (index.html, app.js, style.css)
    scripts/             DNS recon bash tools
    README.md            main human doc (PHRACK-style)
  vulnlab/               intentionally-vulnerable fuzzing TARGET (separate container)
    Dockerfile           alpine + clang + AFL++ + libFuzzer + supervisord
    Makefile             server / libfuzzer / afl / parse-asan targets
    vulnlab.c            buggy HTTP parser (B1 stack overflow, B2 format string)
    fuzz/parse_fuzzer.c  libFuzzer harness; fuzz/parse_afl.c AFL harness
    README.md
  demos/sca-demo/        SCA fixture: committed package-lock pinning lodash 4.17.20
  tests/                 pytest suites (442 tests)
```

## How to run everything

```sh
# build the platform image
cd h4k && docker build -t h4k .

# run it (host networking so it can reach lab hosts + local ollama)
docker run --rm --network host -p 3137:3137 \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
  -e H4K_AI_PROVIDER=ollama -e OLLAMA_BASE_URL=http://127.0.0.1:11434 -e H4K_AI_MODEL=qwen2.5:latest \
  h4k
# → web UI at http://localhost:3137

# or via compose (h4k + vulnlab; add --profile llm for ollama sidecar)
docker compose up --build

# fuzzing lab target (separate)
cd vulnlab && docker build -t vulnlab . && \
  docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab
```

**Important:** after `docker build -t h4k .`, you must `docker run` (or `compose
up`) to start the container — building alone does not leave it running. The API
is what the UI talks to.

## Dev / test loop (host, uses .venv)

```sh
source .venv/bin/activate        # or use .venv/bin/<tool>
make fmt                         # black + isort
make fix                         # ruff --fix
make lint                        # black ruff isort flake8 mypy pylint bandit
make test                        # pytest
make coverage                    # pytest --cov (70% gate)
```

All linters must pass before commit. Tests currently **442 passing** at **79.1%**
coverage (CI gate 70%), pylint ~9.88.

## The API surface (FastAPI, all under /api)

Host recon/scan:
- `POST /scan` `{target, mode, do_dns_recon, do_vuln_scan, try_default_creds, open_sessions, do_attack}`
- `GET /jobs` `?active=true` (job monitor: merges **all** job families), `GET /jobs/{id}`
- `GET /report/{id}`, `POST /scan/{id}/abort`
- `GET /export/{id}?fmt=json|md`
- `GET /neighbors` (ARP)
- `POST /attack`, `GET /attack/{id}`
- `POST /deepattack` (hydra/nikto/sqlmap/smb/dns toolkit)
- `POST /vulnleads`
- `POST /fuzz`, `GET /fuzz/{id}`, `POST /fuzz/minimize`

CTF / lab toolkit (opt-in, each explicit):
- `POST /zap`, `POST /john`, `POST /aircrack`, `POST /tshark/pcap`, `POST /tshark/live`
- `POST /nmap/nse`, `POST /container_escape`, `POST /lateral`, `POST /db_interrogate`

Engagement (persistent memory + cred propagation, engagement router):
- `POST /api/engagement` (declare authorized scope), `GET /api/engagement`, `GET|DELETE /api/engagement/{id}`
- `POST /api/engagement/parse-scope`
- `POST /api/engagement/{id}/ingest` (raw report or `{job_id}`) → asset graph
- `GET /api/engagement/{id}/assets|credentials|graph`
- `GET /api/engagement/{id}/propagate/plan` (dry run), `POST /api/engagement/{id}/propagate` (opt-in)

Source analysis (source router):
- `POST /source/scan` (git URL SAST), `POST /source/scan/upload` (zip/tar/tgz)
- `POST /source/exploit`, `POST /source/exploit/download` (PoC/disclosure skeleton)
- `POST /source/sca`, `GET /source/sca/git`, `GET /source/sca/sbom` (SCA/SBOM)
- `POST /source/triage`, `POST /source/triage/minimize`
- `POST /source/ai`, `POST /source/ai/loop`, `GET /source/ai/models` (Ollama)
- `POST /source/rules/test`, `GET /rules`, `POST /rules/save`, `DELETE /rules/{id}`, `POST /rules/run`
- `POST /source/report/merge`, `POST/GET /source/report/md`
- `POST /source/ossfuzz`

Updater:
- `POST /update`, `GET /update/last`, `GET /update/should`

Health/diagnostic:
- `GET /health`

## Services (api/services/) — quick reference

| module | purpose |
|--------|---------|
| `msfrpc.py` | thin pymetasploit3 wrapper over msfrpcd |
| `scan_pipeline.py` | orchestrator: recon -> fingerprint -> scan -> creds -> attack |
| `modes.py` | stealth / tor / overt config |
| `report.py` | scoring + recommendations + report models |
| `cve_lookup.py` | offline curated CVE matcher (+ refresh) |
| `creds.py` | default-credential archive matching |
| `attack.py` | opt-in Metasploit exploit execution (per-module option validation) |
| `toolkit.py` | opt-in non-Metasploit toolkit (hydra/nikto/sqlmap/...) |
| `discovery.py` | ARP neighbor discovery (arp-scan / cache / msf) |
| `security.py` | traceroute + exposure -> posture heuristic |
| `fuzzer.py` | signal-guided HTTP mutation engine + real libFuzzer crash minimizer |
| `crashes.py` | crash fingerprinting + dedup (N crashes -> M distinct bugs) |
| `vulnleads.py` | EOL/beta/old version flagging |
| `sast.py` | regex heuristics (+ Semgrep merge) SAST |
| `semgrep.py` | real Semgrep engine + test_rule() custom-rule validate |
| `sca.py` | SBOM (trivy) + osv-scanner SCA + scan_secrets + scan_licenses | 
| `triage.py` | crash -> bug-class/CWE/patch-direction/minimize |
| `sanitizer.py` | sanitizer-first: ASan/UBSan flags, trace env, bug-class table, per-finding verify/confirm plans |
| `ai.py` | LLM provider (default local Ollama qwen2.5; OpenAI-compatible opt-in) |
| `ai_loop.py` | AI exploit-first loop: root-cause + minimal trigger (confirm) + patch + verify |
| `rules.py` | persistent custom-rule library |
| `merged_report.py` | one-click consolidate scan+SAST+SCA+fuzz+triage |
| `ossfuzz.py` | OSS-Fuzz-style build+asan+fuzz auto-runner |
| `ingest.py` | source ingest (zip/tar/tgz or git clone), zip-slip-safe |
| `updater.py` | periodic tool/rule/data auto-refresh |
| `engagement.py` | persistent engagement store (scope-enforced asset graph: hosts/services/creds/vulns/attempts) |
| `propagate.py` | credential propagation: replay verified creds across in-scope services |
| `zap.py` | OWASP ZAP headless web-app scanner (spider/active) via REST |
| `john.py` | John the Ripper hash cracking (multi-format CTF flow) |
| `aircrack.py` | aircrack-ng wireless assessment (monitor/capture/crack) |
| `tshark.py` | tshark pcap/live capture, flow/credential/anomaly extraction |
| `container_escape.py` | detect container escape vectors (read-only); explicit exploit helpers |
| `lateral.py` | route/interface map + SSH/chisel tunnel + SMB session helpers |
| `db_interrogate.py` | enumerate local APIs/DBs/configs for flag-shaped secrets |

## Design decisions (the important ones)

1. **Drive Metasploit via msfrpcd (RPC)**, not `msfconsole -x` — structured data.
2. **pymetasploit3** is the client; DB via `db.hosts/services/vulns` with a
   workspace filter (DbManager only exposes connect/status/workspace).
3. **Tor via native `Proxies`** datastore for modules; proxychains for whole-
   process wrapping only.
4. **Aggressive actions are opt-in & off by default** (D5 in RELEASE_NOTES).
5. **Reports are ours** (db_export/db.* + HTML render), not Metasploit Pro.
6. **Curated local CVE/creds JSON** — offline-first, banner-aware (CherryPy !=
   Log4Shell), refreshable.
7. **SAST = Semgrep + regex merged** — Semgrep catches deeper patterns
   (subprocess shell=True), regex covers files Semgrep skips and runs without
   semgrep installed.
8. **SBOM/SCA is honest** — needs a committed lockfile to find CVEs; we never
   fabricate hits.
9. **PoCs are disclosure skeletons, not weapons.**
10. **AI defaults to local Ollama (qwen2.5)**, no key needed; OpenAI-compatible
   as opt-in. `OLLAMA_BASE_URL` allows a sidecar later.
11. **Separate vulnlab container** — sandboxed fuzz target, crash-restart via
    supervisord.
12. **Auto-update periodic task** refreshes semgrep/osv-scanner/trivy + CVE/creds
    (H4K_AUTO_UPDATE=1, interval env).
13. **Engagement scope is enforced in the store, not the UI** — every write and
    every replayed login re-checks the CIDR list. Out-of-scope hosts from a wide
    scan are skipped and reported, never recorded.
14. **Propagation only replays already-verified credentials** — it never invents
    or sprays new candidates, and a ledger means a miss is never re-attempted.
    A pivot edge appears only where a login actually succeeded.
15. **Port breadth is a separate axis from OPSEC mode** — `ScanRequest.depth`
    (`quick`/`standard`/`full`) decides how many ports; every report carries a
    `Coverage` and a partial sweep emits a `[coverage] PARTIAL SCAN` note.
16. **CTF tools are separate opt-in endpoints** — ZAP/John/aircrack/tshark/NSE/
    container-escape/lateral/DB-interrogation each have their own button and
    endpoint; a scan never triggers one. Detection is read-only; exploit helpers
    are only ever called explicitly.

Fuller prose in `RELEASE_NOTES.md` (features + D1–D24) and `ROADMAP.md`.

## Common pitfalls / gotchas

- **`msfrpcd` connect**: client uses `ssl=False` (daemon started `-S true`).
- **`-o -` semgrep**: writes a file literally named `-`; the wrapper writes to a
  temp file (`mkstemp`) and reads it back. Don't "fix" it to stdout.
- **`sys.executable` vs `sys.prefix`**: the .venv symlinks to system python; use
  `sys.prefix` to find `bin/semgrep` etc.
- **osv-scanner needs a lockfile** to surface CVEs; fresh clones without one
  return `packages: []`, `cves: []` (correct, not a bug).
- **Pydantic strictness**: dicts returned from scanners may contain extra keys
  that aren't in the schema — map them explicitly (see the SCA router).
- **bandit `#nosec`**: used with a specific rule id + rationale (e.g.
  `# nosec B603 B607 - fixed argv, no shell`). Don't blanket-skip.
- **`File(...)` in FastAPI** needs `python-multipart` (installed).
- **Tests run offline** — never require a live Metasploit/daemon; the mock MSF
  backend powers the API tests.
- **Auto-update in tests**: `test_updater` monkeypatches `_which`/state; it must
  not hit the network.

## Git / workflow

- Repo is git-tracked locally (`master` → `main`). Always `git add -A` then commit
  with a clear message when asked.
- Only commit when the user asks. Prefer small, focused commits per feature.
- Never commit secrets/keys; keep `.gitignore` up to date (venv, `__pycache__`,
  fuzz artifacts/crashes/corpus).
