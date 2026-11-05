# h4k — session context for AI agents

This file gives an agent everything needed to work safely and correctly on
this repo. Read it before touching code.

## What this is

**h4k** is a self-contained, containerized **offensive-security analysis
platform** for a school capstone. It drives **Metasploit** over its RPC interface
and layers a modern analysis stack on top — coverage-guided fuzzing, static
analysis (Semgrep + heuristics), supply-chain/SBOM checking, an opt-in attack
toolkit, keyless local-LLM (opencode relay) root-cause/patching assistance, and responsible-
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
  Makefile               fmt / fix / lint / test / e2e / coverage / docker
  requirements.txt       runtime deps
  requirements-dev.txt   lint+test toolchain
  RELEASE_NOTES.md       feature + design-decision inventory
  ROADMAP.md             prioritized work
  docs/                  full documentation set (user / dev / security / examples)
  AGENTS.md              this file — read me first
  h4k/                   the main platform image
    Dockerfile           debian12 + postgres + tor + metasploit + offensive tools
    docker-compose.yml   h4k + vulnlab (AI provider is env-configured)
    entrypoint.sh        boot: postgres -> msfdb -> tor -> msfrpcd -> uvicorn
    api/                 FastAPI app
      main.py            app + lifespan (starts periodic updater)
      schemas.py         all pydantic models
      routers/           scan.py, source.py, update.py, net.py, engagement.py
      services/          ~30 modules (see below)
    data/                cves.json, creds.json, wordlists, custom_rules.json (runtime)
    web/                 light dashboard UI (index.html, app.js, style.css)
    scripts/             DNS recon bash tools
    README.md            main human doc (PHRACK-style)
  vulnlab/               intentionally-vulnerable fuzzing TARGET (separate container)
  demos/sca-demo/        SCA fixture: committed package-lock pinning lodash 4.17.20
  tests/                 pytest suites (unit + API) and tests/e2e/ (Selenium)
  docs/                  documentation (see docs/index.md)
```

## How to run everything

```sh
# build the platform image
cd h4k && docker build -t h4k .

# run it (host networking so it can reach lab hosts + the opencode relay)
docker run -d --name h4k --network host -p 3137:3137 \
  -v h4k_data:/opt/h4k/data \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
  -e H4K_AI_PROVIDER=openai_compatible -e H4K_AI_KEYLESS=1 \
  -e H4K_AI_URL=http://127.0.0.1:3777/v1/chat/completions \
  -e H4K_AI_MODEL=opencode/beam-free \
  h4k
# → web UI at http://localhost:3137
# (start the relay first: OPENCODE_MODEL=opencode/beam-free python3 h4k/scripts/opencode_relay.py)

# or via compose (h4k + vulnlab)
docker compose up --build

# fuzzing lab target (separate)
cd vulnlab && docker build -t vulnlab . && \
  docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab

# sandbox mode (no network, no Metasploit, deterministic) — used by CI + demos
cd h4k/api && H4K_SANDBOX=1 H4K_DATA_DIR=/tmp/h4k-demo \
  python3 -m uvicorn main:app --port 3137
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
make test                        # pytest (unit + API)
make e2e                         # Selenium browser suite (headless Chrome)
make coverage                    # pytest --cov (90% gate)
```

All linters must pass before commit. Tests currently **~1367 passing** (+32 e2e); the
coverage gate is 90% (enforced in pyproject). CI runs `lint`, `test` and the
Selenium suite.

## The API surface (FastAPI, all under /api)

Host recon/scan:
- `POST /scan` `{target, mode, do_dns_recon, do_vuln_scan, try_default_creds, open_sessions, do_attack}`
- `GET /jobs` `?active=true` (job monitor: merges **all** job families), `GET /jobs/{id}`
- `GET /report/{id}`, `POST /scan/{id}/abort`
- `GET /export/{id}?fmt=json|md`
- `GET /api/session/report?fmt=json|md|pdf` (one-click assessment; PDF masks passwords)
- `GET /neighbors` (ARP)
- `POST /api/net/ipv6/discover` (NDP table + explicit-CIDR nmap -6, scope-enforced asset ledger)
- `POST /attack`, `GET /attack/{id}`
- `POST /deepattack` (hydra/nikto/sqlmap/smb/dns toolkit)
- `POST /vulnleads`
- `GET /api/kev/check` + `POST /api/kev/enrich` (bundled snapshot) + `POST /api/kev/refresh` (opt-in live)
- `POST /fuzz`, `GET /fuzz/{id}`, `POST /fuzz/minimize`
- `POST /api/fuzz/shard` (N workers, merged registry)
- `POST /api/rate_fuzz` (polite throttle probe + ledger)
- `POST /api/stateful_fuzz` (login → authed-flow fuzz + ledger)
- `POST /container_surfaces` (read-only), `POST /container_fuzz` + `GET /container_fuzz/{id}` (surface fuzz jobs)
- `GET|POST /api/fuzz-profiles`, `DELETE /api/fuzz-profiles/{name}` (auth presets; values never listed)

CTF / lab toolkit (opt-in, each explicit):
- `POST /zap`, `POST /john`, `POST /aircrack`, `POST /tshark/pcap`, `POST /tshark/live`
- `POST /nmap/nse`, `GET /api/nse/suggest` (offline script picker) + `GET /api/nse/services`, `POST /tls/fingerprint` (handshake inventory + C2 leads) + `POST /tls/inventory` (cert inventory + ledger), `POST /nikto`, `POST /ssrf/probe` (metadata SSRF pack + ledger), `POST /nuclei` (+ `GET /nuclei/templates` offline bundle), `POST /gobuster`, `POST /jwt/test` (JWT audit + alg-confusion + ledger), `POST /kubelet/audit` (read-only kubelet exposure audit + ledger), `POST /rbac/audit` (offline K8s RBAC audit + ledger), `POST /container_escape`, `POST /lateral`, `POST /db_interrogate`
- `POST /kerberos/asrep`, `POST /kerberos/kerberoast` (explicit roast, optional John crack)
- `POST /firetv/*` (recon, mdns, ssdp, connect, pair, state, shell, keyevent,
  apps, pull, screenshot, logcat, install, disconnect — Fire TV / Android TV via adb)
- `POST /tryLocalRoot_go_bro` (one-shot local-root assessment: userns +
  docker-group tries + host audit, read-only, no password)
- `POST /api/privesc/suggest` (10-check read-only checklist, sandbox canned)

Engagement (persistent memory + cred propagation, engagement router):
- `POST /api/engagement` (declare authorized scope), `GET /api/engagement`, `GET|DELETE /api/engagement/{id}`
- `POST /api/engagement/parse-scope`
- `POST /api/engagement/{id}/ingest` (raw report or `{job_id}`) → asset graph
- `GET /api/engagement/{id}/assets|credentials|graph`, `GET .../graph/canvas` (deterministic x/y layout for the interactive SVG canvas + PNG export)
- `GET /api/engagement/{id}/propagate/plan` (dry run, spray policy: `max_per_user` + `jitter_max`), `POST /api/engagement/{id}/propagate` (opt-in, lockout ledgered as `locked`)
- `GET /api/engagement/{id}/hygiene` (read-only reuse/weak/default summary + score)
- `POST /api/engagement/{id}/vulns/suppress` (reason + expiry, audit-trailed) + `DELETE .../vulns/suppress` + `GET .../vulns/suppressions|effective`
- `GET /api/engagement/{id}/vault` (masked loot: creds/flags/shares, `reveal=true` unmasks) + `GET .../vault/export` (md/json handoff)
- `POST|GET /api/engagement/{id}/crown-jewels`, `DELETE .../crown-jewels/{id}`
- `GET /api/engagement/{id}/attack-paths` (scored paths to crown jewels)
- `GET /api/engagement/{id}/attck` (technique mapping + detection guidance)
- `GET /api/engagement/attck/techniques` (catalog)
- `POST /api/engagement/sandbox-seed` (sandbox mode only: seeded demo engagement)

Source analysis (source router):
- `POST /source/scan` (git URL SAST), `POST /source/scan/upload` (zip/tar/tgz)
- `POST /source/exploit`, `POST /source/exploit/download` (PoC/disclosure skeleton)
- `POST /source/sca`, `GET /source/sca/git`, `GET /source/sca/sbom` (SCA/SBOM)
- `POST /source/triage`, `POST /source/triage/minimize`
- `POST /source/ai`, `POST /source/ai/loop`, `GET /source/ai/models` (Ollama)
- `POST /source/rules/test`, `GET /rules`, `POST /rules/save`, `DELETE /rules/{id}`, `POST /rules/run`
- `POST /source/report/merge`, `POST/GET /source/report/md`
- `POST /source/reachability` (import-graph dead-code triage)
- `POST /source/secrets/scan` (committed secrets + baseline/allowlist)
- `POST /source/taint/scan` (offline source→sink taint pack + ledger)
- `POST /source/sarif/export`, `POST /source/sarif/import` (SARIF interchange)
- `POST /source/sanitizer/diff` (offline ASan/UBSan/MSan compare)
- `POST /source/ci/gate` (SAST CI gate: threshold + audited ignores)
- `POST /source/sast/delta` (diff-only SAST findings per PR: new/fixed/moved)
- `POST /source/suppress/match` (NOSAST with expiry + owner: suppressed/active/expired)
- `POST /source/verify/fix` (verify-fix retest: persists/fixed/new/flaky + dedup)
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
| `nuclei.py` | opt-in Nuclei CVE-template scan: offline bundle (`data/nuclei-templates`), finding→vuln ledger (`to_ledger`), sandbox stand-in |
| `discovery.py` | ARP neighbor discovery (arp-scan / cache / msf) |
| `security.py` | traceroute + exposure -> posture heuristic |
| `fuzzer.py` | signal-guided HTTP mutation engine + real libFuzzer crash minimizer |
| `container_fuzz.py` | Docker API / kubelet / containerd-framing / HTTP surface fuzzing (job-based) + read-only surface inventory |
| `fuzz_profiles.py` | named auth presets for fuzz runs (values stay server-side) |
| `crashes.py` | crash fingerprinting + dedup (N crashes -> M distinct bugs) |
| `vulnleads.py` | EOL/beta/old version flagging |
| `sast.py` | regex heuristics (+ Semgrep merge) SAST |
| `semgrep.py` | real Semgrep engine + test_rule() custom-rule validate |
| `reachability.py` | import-graph dead-code triage (py/JS/php) + entry guessing |
| `ci_gate.py` | SAST CI gate: threshold + audited ignore list |
| `sast_delta.py` | diff-only SAST per PR: new/fixed/moved + tolerance |
| `suppress.py` | NOSAST directives with owner/expiry: suppressed/active/expired |
| `verify_fix.py` | verify-fix retest: persists/fixed/new/reappeared-flaky + dedup |
| `secret_baseline.py` | committed-secret scan with baseline diff + allowlist |
| `taint_pack.py` | source→sink taint pack (Python/JS/PHP) + scope-enforced ledger |
| `sarif_exchange.py` | h4k↔SARIF 2.1.0 interchange (lossless h4k round-trip) |
| `fuzz_shard.py` | N-worker disjoint-slice coordinator over one locked CrashRegistry |
| `ratefuzz.py` | polite 429/Retry-After backoff probe + throttle characterization |
| `stateful_fuzz.py` | login → authed-flow fuzz with session harvest + ledger |
| `sanitizer_diff.py` | pasted-report ASan/UBSan/MSan coverage compare + one confirming rebuild |
| `jwt_tester.py` | offline JWT audit + capped HMAC crack + live alg-confusion vs marker, ledgered, sandbox canned |
| `ssrf_pack.py` | opt-in metadata SSRF probe pack (AWS/GCP/Azure + encoding bypasses) + scope-enforced ledger, sandbox canned |
| `sca.py` | SBOM (trivy) + osv-scanner SCA + scan_secrets + scan_licenses |
| `triage.py` | crash -> bug-class/CWE/patch-direction/minimize |
| `sanitizer.py` | sanitizer-first: ASan/UBSan flags, trace env, bug-class table |
| `ai.py` | LLM provider (default local Ollama qwen2.5; OpenAI-compatible opt-in) |
| `ai_loop.py` | AI exploit-first loop: root-cause + minimal trigger (confirm) + patch + verify |
| `rules.py` | persistent custom-rule library |
| `merged_report.py` | one-click consolidate scan+SAST+SCA+fuzz+triage |
| `ossfuzz.py` | OSS-Fuzz-style build+asan+fuzz auto-runner |
| `ingest.py` | source ingest (zip/tar/tgz or git clone), zip-slip-safe |
| `updater.py` | periodic tool/rule/data auto-refresh |
| `engagement.py` | persistent engagement store (scope-enforced asset graph + crown jewels) |
| `privesc_suggest.py` | read-only linPEAS-style checklist (10 checks, pass/fail + fix hints, sandbox canned) |
| `kev.py` | KEV/EPSS enrichment from a real stamped snapshot + best-effort live refresh |
| `cert_inventory.py` | TLS cert inventory across hosts (expiry/self-signed/weak, scope-enforced vuln ledger, sandbox canned) |
| `ipv6_discovery.py` | IPv6 NDP table + explicit-CIDR nmap -6 sweep, scope-enforced asset ledger, sandbox canned |
| `tls_fingerprint.py` | active TLS handshake inventory (version/cipher/cert) + exact-match watchlist + heuristic C2 leads, sandbox stand-in |
| `pdf_report.py` | one-click assessment PDF: reportlab render of the session report (passwords masked) |
| `loot_vault.py` | masked loot vault: verified creds + flags + shares, redaction + masked md/json export |
| `kerberos.py` | AS-REP + Kerberoast via impacket (explicit roast, optional John crack, sandbox canned hashes) |
| `nse_suggest.py` | curated service → NSE script map (suggest offline, run explicit) |
| `hygiene.py` | read-only credential hygiene: reuse/weak/default summary + score over verified creds |
| `graph_canvas.py` | deterministic canvas layout for the asset graph (hosts circle, services ring, creds top row; powers the interactive SVG + PNG export) |
| `propagate.py` | credential propagation: replay verified creds across in-scope services |
| `spray_guard.py` | lockout-aware spray policy: per-user cap, jitter, locked-user ledger stop |
| `attack_paths.py` | crown jewels -> scored, evidence-backed attack paths |
| `flag_paths.py` | foothold -> captured-flag chains (one objective per flag host) |
| `attck.py` | MITRE ATT&CK technique mapping + defender detection guidance |
| `sandbox.py` | deterministic offline stand-ins for nmap/hydra/Metasploit (demo + CI) |
| `zap.py` | OWASP ZAP headless web-app scanner via REST |
| `john.py` | John the Ripper hash cracking (multi-format CTF flow) |
| `aircrack.py` | aircrack-ng wireless assessment (monitor/capture/crack) |
| `tshark.py` | tshark pcap/live capture, flow/credential/anomaly extraction |
| `container_escape.py` | detect container escape vectors (read-only); explicit exploit helpers |
| `rbac_audit.py` | offline RBAC manifest audit (* verbs, secret read, escalate/bind, pod create, broad bindings) + scope-enforced ledger, sandbox canned |
| `kubelet_audit.py` | read-only kubelet GETs (/healthz, /pods, /metrics, 10255 probe) + scope-enforced vuln ledger, sandbox canned |
| `firetv.py` | Fire TV / Android TV assessment via adb (recon, mDNS/SSDP sweeps, pair, shell, keyevent, apps, pull, screenshot, logcat, install) + mDNS discovery |
| `privesc.py` | local-root awareness: docker-group/userns tries (read-only, no password) + host audit (SUID/caps/gates/CVEs) |
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
13. **Engagement scope is enforced in the store, not in the UI** — every write and
    every replayed login re-checks the CIDR list. Out-of-scope hosts from a wide
    scan are skipped and reported, never recorded.
14. **Propagation only replays already-verified credentials** — it never invents
    or sprays new candidates, and a ledger means a miss is never re-attempted.
15. **Port breadth is a separate axis from OPSEC mode** — `ScanRequest.depth`
    (`quick`/`standard`/`full`) decides how many ports; every report carries a
    `Coverage` and a partial sweep emits a `[coverage] PARTIAL SCAN` note.
16. **CTF tools are separate opt-in endpoints** — ZAP/John/aircrack/tshark/NSE/
    container-escape/lateral/DB-interrogation each have their own button and
    endpoint; a scan never triggers one. Detection is read-only; exploit helpers
    are only ever called explicitly.
17. **Attack paths are evidence-backed** — a path is built only from *verified*
    credential logins plus the vulnerability inventory, then scored by business
    value, vuln severity and hop count.
18. **Sandbox mode replaces only the leaves** — nmap/hydra/Metasploit become
    deterministic stand-ins; the pipeline, parsers, store and UI stay real.
    This is what makes the Selenium suite and CI hermetic.

Fuller prose in `RELEASE_NOTES.md` (features + D1–D24) and `ROADMAP.md`.
Full documentation in `docs/` (see `docs/index.md`).

## Common pitfalls / gotchas

- **`msfrpcd` connect**: client uses `ssl=False` (daemon started `-S true`).
- **`-o -` semgrep**: writes a file literally named `-`; the wrapper writes to a
  temp file (`mkstemp`) and reads it back. Don't "fix" it to stdout.
- **`-o -` hydra**: same trap, and worse -- it drops a file named `-` into the
  working directory. The password attack parses hydra's stdout instead.
- **never run `black` on `data/*.json`** — black rewrites them with
  Python-style trailing commas, which is invalid JSON and breaks every
  `CveDb` load. Edit JSON by hand or via `python -m json.tool`.
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
- **UI inputs must not use `window.prompt`** — it blocks the browser and cannot
  be driven by Selenium. Use a real form with a `data-testid`.
- **`H4K_DATA_DIR`** overrides the runtime data directory (both
  `neighbors.db` and `engagements.db`). Tests and E2E use a temp dir.
- **nmap XML parsing splits on `"<host "`** — a canned XML must include
  attributes on the `<host>` element or the parser sees no hosts.

## Git / workflow

- Repo is git-tracked locally (`master` → `main`). Always `git add -A` then commit
  with a clear message when asked.
- Only commit when the user asks. Prefer small, focused commits per feature.
- Never commit secrets/keys; keep `.gitignore` up to date (venv, `__pycache__`,
  fuzz artifacts/crashes/corpus).
