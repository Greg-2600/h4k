# h4k — Release Notes

**Version 1.0 · h4k :: Intrusion-Suite**

A self-contained, containerized security **analysis platform** for authorized lab
use. It drives the **Metasploit Framework** over its RPC interface and layers a
modern, cutting-edge analysis stack on top: coverage-guided fuzzing, static
analysis (Semgrep + heuristics), supply-chain/SBOM checking, AI-assisted
root-cause & patching, and responsible-disclosure scaffolding.

> **Authorization is not optional.** Every aggressive action is opt-in and off by
> default, and is intended only for systems you own or have written permission to
> test (school lab range, own VMs).

---

## 1.1 · What's new since 1.0

**tryLocalRoot_go_bro — one-shot local-root assessment** (`services/privesc.py`)
- `POST /api/tryLocalRoot_go_bro` runs every passwordless local-root path in
  one shot: the userns uid-0 try (`unshare -Urm id`, no sudo, no docker), the
  docker-group read-only try, and the full host audit (SUID, file caps + live
  DAC-bypass probe, credential gates, systemd ExecStart/PATH/polkit, CVE
  posture vs the curated DB). Nothing supplies a password, writes a file, or
  runs a payload — tries are `id`/`ls` only, sandbox-gated.
- Console button in the pivot section renders userns/docker verdicts, audit
  vectors and the overall verdict. Research notes live in
  `labs/docker-group-to-root/` and `labs/userns-root-no-sudo-no-docker/`.

**Attack paths to crown jewels** (`services/attack_paths.py`)
- Declare objectives — `POST /api/engagement/{id}/crown-jewels` (`host`, `label`,
  `value` 1–100). Scope-enforced like everything else.
- `GET /api/engagement/{id}/attack-paths` returns scored, evidence-backed paths
  from any plausible foothold to each crown jewel. Only *verified* credential
  logins become edges, so a path is a chain of proof, not a guess.
- `GET /api/engagement/{id}/flag-paths` does the same for captured flags: one
  synthetic objective per flag host, flags attached to each path's final hop
  (`services/flag_paths.py`, `?fmt=md` for a writeup).
- Scoring: `crown_value + Σ(vuln severity) + 25·hops − 12·(hops−1) + foothold
  bonus` — a 2.0 leak that pivots into the DC outranks a 9.8 on an isolated box.
- New Report-page card: **🎯 Attack Paths to Crown Jewels** (add / delete /
  compute, ranked list, ATT&CK techniques per path).

**ATT&CK mapping + detection guidance** (`services/attck.py`)
- `GET /api/engagement/{id}/attck` maps every finding and verified credential to
  MITRE ATT&CK techniques; each technique carries log sources, event IDs and what
  to look for — the defender's language, not just the attacker's.
- `GET /api/engagement/attck/techniques` exposes the curated catalog.
- New Report-page card: **🛡️ ATT&CK & Detection Guidance**.

**Sandbox mode** (`services/sandbox.py`, `H4K_SANDBOX=1`)
- Deterministic stand-ins for the three external dependencies (nmap, hydra,
  Metasploit). Everything above the tool boundary — API, parsers, store, attack
  paths, UI — stays real. No network, no daemon, no credentials.
- `POST /api/engagement/sandbox-seed` seeds a demo lab (3 hosts, 2 pivot
  credentials, 1 crown jewel) for demos and tests.

**Selenium end-to-end suite** (`tests/e2e/`, `make e2e`)
- Headless Chrome drives the real console against a real API in sandbox mode.
- 20 tests: boot/navigation, scope picker, report preview, crown jewels,
  attack paths, ATT&CK panel, and a full autopilot walk.
- The `page` fixture **fails a test on any uncaught JavaScript error** — that is
  how the Report page's missing `renderReportPreview()` was found.
- New CI job runs the browser suite next to lint/tests.

**Bug fixes found by the new suites**
- Report page threw `ReferenceError: renderReportPreview is not defined` on every
  navigation to it (the function was called but never implemented).
- `GET /api/graph` returned **500** whenever an engagement scope was active:
  `out_of_scope_probe(ip)` was called with one argument while `in_scope()` takes
  `(engagement_id, host)`.
- The header scope picker was only populated after a password attack, so it
  showed "scope: none" on a fresh load.
- UI API errors were swallowed: `api()` never rejects, so a 400 was treated as
  success. Added `apiOrThrow()` and used it on the new endpoints.

**Container boot reliability** (`h4k/entrypoint.sh`, `h4k/docker-compose.yml`)
- The Metasploit database is now started, *waited for*, and **verified over
  RPC** before the API comes up. Previously the RPC daemon could start before
  the postgres cluster was reachable, answer "Database Not Loaded", and
  db_nmap would silently find **zero hosts** — a scan of 127.0.0.1 returned an
  empty inventory even though the API was up. The entrypoint now restarts the
  daemon if its DB did not load, and says so in the logs.
- The default compose file uses a **bridge network** so the container's
  postgres/Metasploit ports cannot collide with services already running on
  the host; `docker-compose.host.yml` is the host-network override for
  LAN-wide ARP discovery.
- The Metasploit module catalogue is read from the real pymetasploit3 API
  (`modules.exploits`, `modules.auxiliary`, …). The old code looked for a
  `module_types` dict that does not exist in current versions, so
  `find_exploits()` always returned an empty list — the platform could not
  suggest a single module. Module lookup is now also name-filtered, so it
  costs a handful of RPC calls instead of thousands.

**Capability report** (`services/capabilities.py`, `GET /api/capabilities`)
- Answers the question an operator actually has before a run: *what will work
  here, and what will fail silently?* Installed tools with versions,
  Metasploit reachability **and database state**, the data directory, the
  available wordlists, and plain-language warnings (no Metasploit DB → scans
  come back empty; missing nmap → no inventory; sandbox mode → nothing
  reaches the network).
- The console shows it as a footer badge (green/amber), and
  `scripts/sanity_check.py` asserts on it.

**Banner-aware CVE matching** (fixes a critical false positive)
- The matcher keyed the version ranges off the CVE's generic product (`ftp`)
  instead of the product actually detected on the wire (`vsftpd`), and when a
  version was known but no range existed it fell through to "vulnerable".
  A **vsftpd 3.0.3** host was therefore flagged with the **2.3.4 backdoor**
  CVE. Now: out-of-range versions exclude the CVE, and a match that cannot be
  ruled out is marked `_version_verified: false` instead of being asserted.

**Engagement snapshots + attack-path export**
- `GET /api/engagement/{id}/export` → a portable snapshot; `POST .../import`
  merges one back in, scope-checking every host and reporting the ones that
  were skipped.
- `GET /api/engagement/{id}/attack-paths?fmt=md` → a delivery-note writeup.

**Passive auto-scan on boot** (`services/auto_scan.py`, `GET/POST /api/map*`)
- As soon as the API comes up it detects the local subnet from the default
  route, creates a default `auto-scan` engagement, and runs a recon-only
  pass (ARP discovery, nmap fingerprint, CVE correlation — **no credentials,
  no exploitation**). It re-scans on a cadence so the map stays current.
- The map is live at `GET /api/map` and in the console footer
  (`auto-scan: running · 12 hosts · 34 services · 3 vulns`), with a toggle.
- Configurable via `H4K_AUTO_SCAN`, `H4K_AUTO_SCAN_CIDR`,
  `H4K_AUTO_SCAN_INTERVAL`, `H4K_AUTO_SCAN_DEPTH`.
- This is the feature the user asked for: "start the container, and have it
  start building a network and service map looking for vulnerabilities right
  off the bat, passively."

**Job monitor honesty + Recon that actually renders**
- Every background runner flips `queued` → `running` up front (guarded so a
  pre-start abort is never clobbered). Previously the monitor read "queued"
  for entire multi-minute runs while progress advanced underneath.
- `GET /api/neighbors` now merges fingerprinted services from `neighbors.db`,
  so the Recon Services table fills after a fingerprint — previously it could
  never render, because the UI read `res.hosts` while the API sends
  `res.neighbors`. `GET /api/jobs` and `GET /api/jobs/{id}` now cover every
  job family (scan, attack, deepattack, fuzz, container-fuzz, neighbors,
  fingerprint, passattack).
- Fingerprint nmap runs `-sV -O`; the `<osclass>` parser no longer requires
  adjacency, so real-world OS guesses land in `os_guess`.

**Documentation** (`docs/`)
- New full documentation set: quickstart, concepts, workflows, UI guide,
  safety, troubleshooting, architecture, API reference, service reference, data
  model, testing guide, contributing, release process, threat model, scope
  enforcement spec, secrets handling and runnable examples.

---

## 1 · What it is

A browser-based terminal (web UI → FastAPI → Metasploit MessagePack-RPC) plus a
standalone **fuzzing lab** container. It moves from "scan a host" to "analyze the
software you actually run" — the workflow real security teams use.

```
+----------+   HTTP/JSON   +--------------+  MessagePack-RPC  +-----------------+
| browser  | ------------->|   FastAPI    |------------------>|  msfrpcd         |
| terminal | (0.0.0.0:3137)|   (api/)     |     55553         |  Metasploit FWDB |
+----------+               |  + SAST/SCA/ |                   +-----------------+
                           |  + fuzz/ AI  |   subprocess        +-----------------+
                           |  + triage    |   osv/trivy/semgrep |  vulnlab (lab)  |
                           +--------------+   git/curl         |  fuzzing target  |
                                                               +-----------------+
```

Two runnable images:

| image     | purpose                                                        |
|-----------|----------------------------------------------------------------|
| `h4k`     | the full analysis platform (Metasploit + SAST + SCA + AI + UI) |
| `vulnlab` | intentionally-vulnerable fuzzing target (coverage-guided)     |

---

## 2 · Features

### 2.1 Host recon & scan

- **Target** — IP, hostname, or CIDR. Normalized automatically.
- **Three OPSEC modes**
  - `stealth` — `-sT -T2 --top-ports 100`, no OS detect, low retries.
  - `tor` — module traffic routed via `Proxies socks5:127.0.0.1:9050` + proxychains.
  - `overt` — `-sS -T4 -sV -O --top-ports 500 --min-rate 1000`.
- **Port scan** via `db_nmap` → hosts/services into the Metasploit DB.
- **Fingerprinting** — banners + `whatweb` → vendor / model / OS / technology.
- **Service enumeration** — aux scanner families for http, smb, netbios, msrpc
  (dcerpc), ldap, ftp, ssh, rdp, mysql, mssql, postgres, telnet.
- **Reverse DNS (PTR)** on discovered IPs, with public-resolver fallback.
- **DNS recon** (domains) — `dns_dumpster`, `sub_domain_lookup`, `dnstracer`,
  `traceroute`, `dig`.
- **Neighbor discovery** — `arp-scan`, arp cache, MSF `arp_sweep` → IP/MAC/vendor.
- **Security-posture heuristic** — traceroute + exposure signals → high/medium/low
  level + 0–100 score + confidence (declarative guess, clearly labeled).

### 2.2 Vulnerability analysis

- **Local curated CVE archive** (`data/cves.json`) — banner-aware matching of
  high-signal CVEs (EternalBlue, BlueKeep, Log4Shell, Heartbleed, ...), with
  suggestions of relevant Metasploit modules.
- **Version leads** (`/api/source/vulnleads`) — flags EOL / very-old / beta /
  unusual service versions from banners (OpenSSH, Apache, nginx, PHP, IIS,
  Tomcat, vsftpd...) as research leads.
- **Default-credential archive** (`data/creds.json`) — universal list +
  vendor/make-model creds (routers, Pi, NAS, IP cams, Windows/macOS...), all
  **opt-in**, every attempt recorded with verified/tested flag.
- **Recommendations** — ranked "what to attack" with module + difficulty + CVE refs.

### 2.3 Active (opt-in, lab-only) actions

- **Metasploit exploit window** — opt-in, per-service exploit modules; verified
  creds are passed through; per-module option validation.
- **Non-Metasploit toolkit sweep** (`/api/deepattack`) — hydra, john, sqlmap,
  nikto, gobuster, ffuf, smbmap/smbclient, dnsrecon, masscan, tcpdump/tshark,
  netcat/socat — gated behind its own opt-in button.
- **Scan abort** — `/api/scan/{id}/abort` with graceful stop between stages.

### 2.3b Engagements & credential propagation

A per-target scan is stateless and dies with the process. An engagement is not.

- **Persistent engagement store** (`/api/engagement`, SQLite) — hosts, services,
  credentials, vulns and an attempt ledger accumulate across scans and restarts,
  so the operator keeps one growing picture instead of re-scanning and forgetting.
  The DB is `0600`: it holds verified credentials in the clear.
- **Scope is the boundary, enforced server-side.** An engagement declares its
  authorized CIDRs. Every write re-checks them, so a mistyped target in the UI
  cannot silently widen the engagement. Out-of-scope hosts from a wide scan are
  skipped and *reported back* (`skipped_out_of_scope`), never recorded.
- **Credential propagation** (`/api/engagement/{id}/propagate`, opt-in) — replays
  credentials *already verified in the engagement* against every other in-scope
  service that has a login module. Humans reuse passwords; this finds where.
  A dry-run `…/propagate/plan` shows the blast radius before anything is sent.
- **Provenance, not inference.** One credential found on three hosts is one
  credential and three `cred_access` rows, and the asset graph emits a `pivot`
  edge listing exactly the hosts where a login *actually succeeded*. Nothing is
  inferred from "these hosts both run ssh" — consistent with D16.
- **Attempt ledger** — a failed replay is recorded too, so re-running is cheap
  and the attempt count stays a real cost bound (`MAX_ATTEMPTS = 500`).


### 2.4 Software analysis on source you provide

- **Ingest** — upload `.zip`/`.tar`/`.tar.gz` **or** clone a git/GitLab URL,
  zip-slip–safe, size-bounded.
- **SAST** — two engines merged:
  1. **Semgrep** (real rule set, finds patterns regexes miss), and
  2. **regex heuristics** (SQLi, command injection, path traversal, eval,
     deserialization, C buffer/format-string, hardcoded secrets, insecure HTTP,
     debug leaks).
- **Local TLS interception lab** (`/api/net/tls/*`) — build a private CA, sign
  a localhost cert, install the CA into the container's trust store, and expose
  an owned plain-HTTP lab target over HTTPS on loopback so fuzzer/SAST can
  target an `https://` web app you own with a cert clients trust. All loopback,
  opt-in.
- **Custom SAST rule library** — author, **save**, list, and re-run rules over a
  whole git tree (`/rules/save` · `/rules/list` · `/rules/run`).
- **Semgrep offline registry** — a bundled rule pack (21 rules across Python,
  JS/TS, Java, C/C++, bash) so SAST runs fully offline; fixed the `--offline`
  flag on newer semgrep that was silently returning no findings.
- **SCA / SBOM** (`/api/source/sca`) — build a CycloneDX SBOM (trivy) and
  cross-check dependencies against the **OSV DB** (osv-scanner) → known CVEs.
  Surfaces **license** findings (trivy `--scanners license`) and hardcoded
  **secret** candidates (regex heuristic) alongside the CVEs; the SBOM is
  downloadable (.cdx.json).
- **Triage** (`/api/source/triage`) — crash candidate → bug-class + CWE +
  minimized trigger + concrete patch direction + confirm steps.
- **PoC / disclosure skeleton** (`/api/source/exploit` · `.../download`) —
  language-aware, clearly-labeled proof-of-concept for responsible disclosure,
  downloadable as a file.
- **AI root-cause + patch** (`/api/source/ai`) — defaults to **local Ollama**
  (qwen2.5) producing `ROOT_CAUSE` / `PATCH_CANDIDATE` / `VERIFY`;
  OpenAI-compatible endpoints supported; degrades gracefully when unreachable.
- **AI exploit-first loop** (`/api/source/ai/loop`) — from a crash/SAST finding
  produces `ROOT_CAUSE` → a minimal **`TRIGGER`** (a PoC that *confirms* the
  vuln on code you own) → **`PATCH_CANDIDATE`** → **`VERIFY`**. Exploit to
  confirm, then fix — still clearly scoped to authorized systems, non-weaponized.

### 2.5 Fuzzing lab (separate `vulnlab` container)

- **Intentionally-vulnerable HTTP server** (stack overflow + format string),
  supervisord-restarted after each crash.
- **Coverage-guided fuzzing** — libFuzzer + ASan (finds the overflow in seconds)
  and AFL++ harnesses — the modern way vs. blind mutation.
- The h4k black-box fuzzer demonstrates the crash→restart→retrieve loop.

### 2.5b Crash dedup & real minimization (zero-day hunting)

- **A fuzzer reports events, not bugs.** One stack overflow in a length field
  produces thousands of distinct crashing inputs and exactly one bug. The
  registry fingerprints each crash by the sanitizer's own error class plus
  normalized top frames, so `N crashes → M distinct bugs` is a real number.
  Fingerprints survive ASLR (load addresses stripped), source line drift,
  and truncated stacks — the volatile parts are removed before hashing, the
  faulting function and module are what is kept.
- **Black-box signals are never counted as confirmed bugs.** A connection
  reset names no code path, so it is fingerprinted on signal + target and
  labelled an unconfirmed lead. Only sanitizer-backed fingerprints count as
  bugs. The run reports `confirmed_bugs` and `unconfirmed_leads` separately
  from `total_occurrences` so the two can never be confused.
- **A real mutation engine**, seeded and reproducible: bitflip, byte-set,
  arithmetic, boundary-value, dictionary, block delete/repeat, splice, and
  stacked havoc. The corpus grows when an input finds a fingerprint the run
  has not seen. Same seed → same mutation sequence, so a crash replays.
- **Minimization that minimizes.** libFuzzer `-minimize_crash=1` runs in a
  clean temp cwd and the smallest `minimized-from-<sha1>` artifact is read
  back; empty artifacts are skipped and the result is only reported when it
  is genuinely smaller. Measured: 4027 → 256 bytes (93.6%) on vulnlab B1,
  landing exactly on `BUF_SIZE` — the true overflow point.

### 2.6 Platform / UX

- **Light operations dashboard** (no build step, plain HTML/CSS/JS): a sticky
  canonical-target bar, live status pills, a live console, and four
  always-reachable sections instead of a linear wizard —
  **Recon → Vulnerabilities → Exploit**, plus **Research** for code you own.
  Recon declares authorized scope, discovers hosts and scans; Vulnerabilities is
  one severity-ordered triage list (findings, vulns, hosts, credentials,
  posture, version leads, fingerprints, notes) with search, a severity filter
  and per-tab counts; Exploit carries the selected finding into a Metasploit
  drawer, a deep-toolkit sweep, the planner's ranked vectors and the attempt
  log; Research holds source analysis, SBOM/SCA, fuzzing, OSS-Fuzz, triage,
  the disclosure-PoC skeleton, local-LLM assist and the custom-rule library.
  Every section is reachable from anywhere, so a finding never traps you in a
  sequence. The nav badges answer "is anything waiting for me" (recon hosts,
  findings to triage, attempts made, triage rows) without opening anything.
  Selecting a finding jumps to Exploit with host, port, service and a pinned
  module; attack output is written to the exploit drawer's own pane, never into
  the research disclosure PoC. Aggressive actions stay behind an explicit
  opt-in checkbox group and a `confirm()` that names the target and module.
- **Always-on job monitor** (`/jobs`) listing every running scan / attack /
  deepattack / fuzz job with a history tab, so an in-flight job is visible no
  matter which tab started it. A deepattack or fuzz job still running after a
  page reload is re-adopted automatically — its own panel reconnects instead of
  asking the operator to re-run the action.
- **Report export** to `.json` / `.md`.
- **Phrack-ezine README view** at `/readme`.
- **Scan cache** (5 min per target+mode) to avoid re-probing.
- **Release packaging** — `scripts/release.sh <ver>` builds/tags the image and
  prints the one-line `docker run`.
- **REST surface** (see §5).

---

## 3 · Design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | **Drive Metasploit via msfrpcd (MessagePack-RPC)**, not `msfconsole -x` | RPC returns structured data and supports `module.*`, `db.*`, `session.*`, `job.*`; `-x` output is hard to parse. |
| D2 | **pymetasploit3** as the Python client | De-facto maintained client; DB queries via `db.hosts/services/vulns` with a workspace filter (pymetasploit3's DbManager only exposes connect/status/workspace). |
| D3 | **`db_nmap` for port scan** | Reuses the framework's own nmap + DB import path instead of reimplementing. |
| D4 | **Native `Proxies` datastore for Tor**, not proxychains for modules | `set Proxies socks5:127.0.0.1:9050` is the supported per-module route; proxychains is used only for whole-process wrapping. |
| D5 | **Aggressive actions opt-in & off by default** | A normal scan only reconnoiters/advises; creds, exploits, deep toolkit, fuzz, and AI-assist all require an explicit switch. Keeps it a defensible lab tool. |
| D6 | **Reports are our own, not Metasploit Pro** (db_export/db.* + HTML render) | Community Framework has no Pro-only report builder; we render findings ourselves and export JSON/MD. |
| D7 | **Curated local CVE/creds JSON, refreshable, offline-first** | Small, fast, works without network; banner-aware matching avoids false positives (e.g. CherryPy ≠ Log4Shell). |
| D8 | **SAST = Semgrep + regex heuristics merged** | Semgrep catches deep patterns (e.g. `subprocess shell=True`); regex covers files Semgrep skips and runs even when semgrep isn't installed. Never trust heuristics as ground truth. |
| D9 | **SBOM/SCA is accurate, honest** | Requires a committed lockfile to find CVEs; we do not invent findings. The container just *enables* the tools (trivy + osv-scanner). |
| D10 | **PoCs are disclosure skeletons, not weapons** | Teaches the *method* (fuzz → crash → minimize → fix → disclose) without shipping weaponization. |
| D11 | **AI defaults to local Ollama (qwen2.5), no key needed** | Private, offline, deterministic enough for root-cause/patch; OpenAI-compatible as an option. `OLLAMA_BASE_URL` allows a sidecar later. |
| D12 | **Separate `vulnlab` container for the fuzz target** | Isolation, sandboxed on loopback; compiled without stack canaries and restarted by supervisord so you see crash→recovery. |
| D13 | **In-memory job stores + 5-min cache** | Single-lab deployment; avoids re-scanning the same box, keeps state simple. |
| D14 | **Fingerprinting via banners + whatweb, posture via traceroute** | Cheap, no extra auth; posture is a labeled heuristic (high = more exposed), not a claim. |
| D15 | **Strict static-analysis hygiene** | black/ruff/isort/flake8/mypy/pylint/bandit all green; bandit-nosec annotations carry rationale. |
| D16 | **Sanitizer-first, and honest about its limits** | Every SAST finding and fuzz candidate carries the exact ASan/UBSan flags, runtime env, and the trace line a sanitizer would print. We only claim what a sanitizer can adjudicate: for injection/traversal/secret classes it says "a sanitizer can't confirm this", and a black-box signal gets a *replay recipe + candidate classes*, never a verdict. A static hit is a hypothesis until you run it. |
| D17 | **Tools report failure instead of pretending** | Every openssl/socat/tool step's return code is checked and the failing step is named, so a broken lab says *why*. States that are legitimately incomplete (certs built but CA not yet trusted) return an explicit `next` action rather than a bare `false`. Same principle as D16 applied to the tool layer. |
| D18 | **Scope is enforced in the store, not the UI** | An engagement declares its authorized CIDRs and every write and every replayed login re-checks them. A wrong target typed into the UI cannot widen the engagement, and out-of-scope hosts are skipped and reported rather than quietly recorded. Authorization is a property of the data model, not of a form. |
| D19 | **Propagation replays proven credentials, never invents them** | It reuses only credentials already verified against an in-scope host. It cannot spray new candidates, and a miss is ledgered so it is never retried. A pivot edge is drawn only where a login genuinely succeeded — reachability is measured, never assumed from "these hosts run the same service". |
| D20 | **A fuzzer counts bugs, not crashes** | Raw crash counts are the classic way to oversell a fuzz run: 40000 crashes can be 3 bugs. Crashes are fingerprinted by faulting code path (ASLR and line numbers stripped) and deduped, and the report always shows distinct bugs *alongside* total crashes. Black-box signals that name no code path are counted as unconfirmed leads, never as bugs. |
| D21 | **A reducer that reports no reduction is worse than none** | The old minimizer returned the unmodified crash file on both its success and failure branch — two identical branches, the signature of a reducer that never reduced. It now reads back the artifact libFuzzer actually wrote and only claims a reduction when the result is genuinely smaller, so "minimized" always means minimized. |
| D22 | **Signal-guided is not coverage-guided, and the tool says so** | The HTTP fuzzer has no instrumentation and therefore no edge feedback, so it cannot distinguish "reached new code" from "looks new". `stats.coverage_guided` is `false` in the output and the UI says so, pointing at the libFuzzer path for real coverage guidance. Marketing blind mutation as coverage guidance would be the same lie in a different coat. |
| D23 | **Port breadth is its own axis, and a partial sweep says so** | Stealth/tor/overt decides *how* we probe; a separate `depth` (quick/standard/full) decides *how much*. Previously every mode shipped `--top-ports`, so an "overt" scan silently checked a few hundred ports and could report nothing open on 11434/18799. Every report now carries `coverage` (`ports_spec`, `max_ports`, `complete`) and a partial sweep emits a `[coverage] PARTIAL SCAN` note: absence of a finding is not absence of a service. |
| D24 | **CTF tools run only when asked, and each names its target** | ZAP, John, aircrack, tshark, NSE, nikto, gobuster, sqlmap, container-escape, lateral and DB-interrogation are separate opt-in endpoints with their own UI buttons — a scan never triggers a web scan, hash crack or wireless capture. Read-only detectors (container escape, route map) stay read-only; exploit helpers (ptrace/cgroup/docker-socket, tunnels) are never called by detection. This keeps the "aggressive actions are explicit" rule (D5) true of the new surface as well. |
| D25 | **A job you cannot see is a job you cannot trust** | Every job family used to keep its own private dict with only a `GET /{job_id}` route, so a hydra sweep was visible only in the browser tab that happened to start it: reload, second tab, or `curl` and it vanished mid-run while still burning the target. `GET /api/jobs` now merges all four stores into one honest list, and the UI polls it continuously. A family with no meaningful percentage reports `progress: null` and renders a "working" pulse — a fake `0%` bar reads as stalled, which is the opposite of the truth. |

---

## 4 · Build & run

```sh
# h4k platform
docker build -t h4k h4k/
docker run --rm --network host -p 3137:3137 \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
  -e H4K_AI_PROVIDER=ollama -e OLLAMA_BASE_URL=http://127.0.0.1:11434 -e H4K_AI_MODEL=qwen2.5:latest \
  h4k
#  → http://localhost:3137

# optional: local AI (already running on this host)
# optional: fuzzing lab target
docker build -t vulnlab vulnlab/
docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab
```

Or `docker compose up --build` (h4k + vulnlab together).

---

## 5 · REST surface

```
POST  /api/scan                       {target, mode, try_default_creds, do_attack...}
GET   /api/jobs ?active=true          all job families merged, newest first
GET   /api/jobs/{id}                  status · progress · log · report
GET   /api/report/{id}
POST  /api/scan/{id}/abort
GET   /api/export/{id}?fmt=json|md
GET   /api/neighbors                   ARP sweep
POST  /api/attack                      opt-in Metasploit exploit
POST  /api/deepattack                  opt-in toolkit sweep (hydra/nikto/...)
POST  /api/vulnleads                   EOL/beta/old version leads
POST  /api/fuzz + /api/fuzz/{id}        lab fuzzer, dedup'd by bug fingerprint
POST  /api/container_surfaces|container_fuzz
                                        container-surface fuzzing (Docker/kubelet/gRPC/HTTP)
POST  /api/source/scan                 clone+SAST (git URL)
POST  /api/source/scan/upload          upload+SAST (zip/tar/tgz)
POST  /api/source/exploit              PoC skeleton
POST  /api/source/exploit/download     PoC as file
POST  /api/source/sca · GET /sca/git   SBOM + SCA/CVEs
POST  /api/source/triage · .../minimize
POST  /api/source/ai                   AI root-cause + patch (Ollama/OpenAI)
POST  /api/source/rules/test           custom Semgrep rule validation
POST  /api/zap                          opt-in OWASP ZAP web-app scan
POST  /api/john                         opt-in John hash cracking (CTF)
POST  /api/aircrack                     opt-in wireless assessment
POST  /api/tshark/pcap · /tshark/live   pcap / live capture analysis
POST  /api/nmap/nse                     nmap vuln NSE scripts
POST  /api/nikto                        standalone nikto web scan
POST  /api/gobuster                     standalone gobuster content discovery
POST  /api/container_escape             container escape vector check (read-only)
POST  /api/firetv/recon|mdns|ssdp|connect|pair|state|shell|keyevent|apps|pull|screenshot|logcat|install|disconnect
                                        Fire TV / Android TV via adb (opt-in)
POST  /api/lateral                      route/interface map (read-only)
POST  /api/db_interrogate               local API/DB/flag interrogation
GET   /api/health
```

---

## 6 · Quality

- **442 unit/API tests**, no live daemon required (mocked MSF backend).
- Linters: **black, ruff, isort, flake8, mypy, bandit — all clean**; **pylint 9.90/10**.
- Container builds clean; AI + SCA + SAST verified live in the running container.

---

## 7 · Known limitations (honest)

- **SCA needs a committed lockfile** to surface CVEs; fresh clones without one
  return no findings (by design — no fabricated CVEs).
- **SAST regex/Semgrep flag candidates**, not proven bugs — the analyst confirms.
- **Security posture** is a heuristic triage gauge, not an authoritative assessment.
- **AI output is unvalidated** — treat as a diagnostic *assist*; verify on systems
  you own. Requires Ollama (or an OpenAI key) to be live; degrades otherwise.
- **The HTTP fuzzer is signal-guided, not coverage-guided.** No instrumentation
  means no edge feedback, so its corpus grows on *finding something new*, not on
  *reaching new code* — a strictly weaker notion of interestingness. Use the
  libFuzzer/AFL path for real coverage guidance.
- **A black-box crash can only be *confirmed* if the target leaks its trace.**
  A service that dies quietly gives you a connection reset, which names no code
  path and therefore stays an unconfirmed lead. To confirm, rebuild the target
  under ASan/UBSan and replay — that is what the per-candidate recipe is for.
- **The OSS-Fuzz runner does not generate harnesses.** It clones, runs your
  `build_cmd`, and fuzzes `fuzz_bin`; writing `LLVMFuzzerTestOneInput` and
  wiring sanitizers into the build is still the operator's job.
- **Job state is in-process memory only.** A container restart, reload, or crash
  drops every job and its history; the monitor then shows an empty list rather
  than stale rows. Fine for a single-lab deployment, not a multi-user daemon —
  there is no job table in Postgres and no resumption across restarts.
- **No binary analysis, reversing, or CTF-category tooling.** No Ghidra/radare2/
  angr/pwntools integration and no pwn/crypto/stego/forensics/web-CTF helpers.
  These are real gaps, not hidden features.

---

## 8 · Layout

```
Dockerfile · docker-compose.yml     platform image (+ vulnlab service)
api/
  main.py · schemas.py · app_state.py
  routers/  scan.py · source.py
  services/ msfrpc, scan_pipeline, modes, report, cve_lookup, creds,
            attack, toolkit, discovery, security, fuzzer, crashes, vulnleads,
            sast, semgrep, sca, triage, ai, ingest
data/       cves.json · creds.json · users/passwords/web-words lists
web/        light dashboard UI (html/css/js)
scripts/    DNS recon bash tools
vulnlab/    intentionally-vulnerable fuzzing target + harnesses
tests/      unit + API tests
```

**h4k**, out.

## Operations-UI era (post-D24)

The operations UI collapsed into a single top-to-bottom recon flow on the Recon
page (nav: Recon / Graph), driven by two persistent stores:

- **neighbors.db** — discovered hosts, fingerprinted open services, correlated
  CVE/lead findings, credentials found by password attacks, and exploit sessions
  opened. `GET /api/session` reports counts; `POST /api/session/reset` starts a
  fresh recon session (engagement store deliberately kept unless asked).
- **Service lifecycle** — Live Network discovery (ARP, async job w/ live cards)
  → per-host nmap fingerprint (`/api/neighbors/fingerprint`) → offline CVE db +
  version-heuristic correlation (`_match_service_vulns`; auxiliary/post-only
  modules are recon leads and never surface as exploitable findings)
  → Likely Vulnerable card (severity-sorted table + CVE-db staleness indicator
  with weekly refresh button) → Exploit Setup card (module prefilled from the
  CVE db's msf hint; `POST /api/attack` was previously missing its route) →
  Common Password Attack card (hydra over ssh/ftp/telnet/mysql/http-basic;
  found creds persist and unlock credential-driven modules on later attacks)
  → Default-Cred Targets card (every fingerprinted service hydra can attack,
  with a read-only HTTP con probe for web surfaces) → Network Graph (nodes
  ring red for vuln-bearing hosts, 💀 for hosts with live sessions).

Weekly CVE refresh job runs in the app lifespan (`H4K_CVE_WEEKLY`, 7-day
default) and refreshes the *live* matcher instance; the periodic tool updater
was fixed to do the same instead of writing the data file behind a throwaway
instance. The offline curated CVE db grew from 31 to 48 entries.

Aggression rules unchanged (D5, D24): discovery + CVE correlation read the
network; nothing brute-forces or exploits without an operator pressing a
button, and every aggressive card names exactly one host/service.

## Autopilot

A dedicated page turns the recon flow into one supervised walk of the local
network: discovery -> fingerprint -> CVE correlation -> hydra password attacks
(8 best targets, 120 s each) -> pinned-module exploit attempts (top 10, CVE-db
module hints first, static service map as fallback, verified creds from the
password stage feed credential-driven modules). Requirements: an active
engagement scope — without one the endpoint refuses with 403. Out-of-scope
neighbors are logged and skipped, nothing outside the scope is ever recorded,
and the live log named-verbatim's every brute-force and exploit attempt. Stop
button ends stages at the next checkpoint.

### Engagement loop (wave 8)

- Fingerprint/cred/vuln events mirror into the **active engagement's**
  scope-checked asset graph (`upsert_asset/upsert_service/record_vuln/
  record_credential`), so the engagement graph page and the propagation
  planner fill from live recon.
- Graph page gains a **🧬 Propagation plan** button: dry-run blast radius of
  replaying verified credentials across in-scope login-capable services —
  no network calls in a plan, execution stays a separate explicit POST.
- **Autopilot deep-web flag** (`{"deep_web": true}` or the second start
  button): nikto + gobuster against up to 6 http surfaces, findings logged
  per surface.
- AI triage provider is now **keyless opencode relay** (host-side; see
  scripts/opencode_relay.py); compose no longer ships an LLM sidecar.
- Autopilot runs persist and appear in the session report; opened sessions are
  automatically post-exploit recon'd (sysinfo/getuid/hashdump → session_recon).

## Public-repo hardening (2026-11-04)

CI was red underneath a broken `make setup` (`.venv/bin/python` before the
venv exists — every fresh runner failed before lint). Fixed setup to
`python3 -m venv` + install both requirements files (missing
`python-multipart` was killing the API in e2e), gave `test`/`coverage`
`.venv/bin` on `PATH` + `--ignore=tests/e2e`, added `pythonpath=[".",
"h4k/api"]` so `from h4k.api...` imports resolve, `nosec`'d four bandit
false positives, and skipped four live-host privesc assertions on
`GITHUB_ACTIONS` (runners have passwordless sudo/docker by design).
E2E crown-jewel waits raised 20s → 60s (slow-runner flakes).

GitHub: ruleset `main protection` (PR + `lint-test` + `e2e` green),
`delete_branch_on_merge`/`allow_update_branch`/`allow_auto_merge` on,
Dependabot security updates on, CodeQL default setup on, topics +
`lodash` fixture ignore. License back to pure MIT (detection flipped
`Other` → `MIT`). Dependabot queue worked: actions bumps merged,
lodash fixture declined (intentionally vulnerable), debian 13 deferred
(`buster` metasploit repo vs new base — needs a tested build).

## CVE refresh fix + container re-verify (2026-11-04)

`REFRESH_URL` pointed at `.../main/data/cves.json` (404 — the dataset
lives at `.../main/h4k/data/cves.json`), so every startup/weekly/updater
refresh silently kept the bundled snapshot. Fixed + regression test
pinning the path. Full local verification on this host: `make lint`
green, pylint 9.80, `make test` 1340 passed / 3 skipped, `make e2e`
29 passed / 3 skipped (chromium + chromedriver), crown-jewel waits at
60s holding green.

## Lab Watch — continuous change detection (2026-11-04)

Every auto-scan pass now snapshots the in-scope estate and diffs it against
the previous pass: new/vanished hosts, opened/closed services, changed
banners, new/cleared CVE matches. Stored per engagement with retention
(old snapshots pruned, out-of-scope hosts never recorded). Surfaced in a
Score-tab card (snapshot-now + history), the session report, and the merged
report; `scripts/qualify.py` gained a watch stage. Scope enforcement reused,
not reinvented: snapshots filter through `in_scope` like ingest does.

## Lint + test hygiene (2026-11-04)

`make lint` now actually lints everything: shellcheck covers
`h4k/scripts/` too (fixed real quoting bugs in the shipped DNS recon
scripts), hadolint runs on all three Dockerfiles via a pinned config
(`.hadolint.yaml` documents the accepted rolling-image exceptions), and
`shellcheck-py` moved into requirements-dev so CI stops skipping shell
lint. Lab Watch closed the loop (#16): change digest badge, per-engagement
mode/retention prefs, verify-fix flow, trends view, qualify stage.
Unit 1367 + e2e 32 green in containers.

## Blue-team handoff (2026-11-04)

Engagements now export defender artifacts: ATT&CK Navigator layer JSON,
experimental Sigma bundle (one rule per observed technique, evidence-linked,
marked tune-before-use), and a written defender summary. Score-tab card with
Layer/Sigma/Writeup downloads; session report carries the observed technique
list. Strictly evidence-derived — no fabricated telemetry.

## Self-healing stack (2026-11-04)

The msfrpcd watchdog is now a real supervisor: postgres, msfrpcd, tor, and
the auto-scan thread are probed on a cadence (H4K_SUPERVISOR_INTERVAL, 60s
default) and restarted within a per-service budget (3 per 10 min, then
degraded instead of hot-looping). /api/health reports per-service state and
restart counts; the ops rail shows daemon status. Qualify ends with a chaos
stage: SIGKILL msfrpcd in the runtime container and require recovery with a
recorded restart before teardown.

## Debian 13 (trixie) base image (2026-11-05)

Base moved from `debian:12-slim` to `debian:13-slim`, proven the hard way:
fresh no-cache build, fresh boot (postgres 17 + msfrpcd + tor + API all
healthy), and a full 24-stage qualify workout on the trixie stack. Trixie
ships apt-owned Python packages without RECORD files, so system-site pip
replaces fail — `--ignore-installed` on all pip installs (matching the
existing impacket precedent). Also unmasked a latent hazard: the trailing
`|| true` (meant for `pip check`) swallowed whole-layer install failures;
`pip check` is clean so it now fails loudly, plus curl retries on every
network fetch and a pinned trivy tarball instead of install.sh.

## Backlog #34 — chisel/sshuttle pivot

`POST /api/net/tunnel` starts a loopback-only SSH `-D` forward or
chisel server and tracks it in a registry with liveness;
`POST /api/net/tunnel/scan` TCP-scans a target *through* the SOCKS
proxy with a stdlib SOCKS5 handshake (no new deps) plus a banner grab
per open port. `DELETE /api/net/tunnels/{id}` kills and forgets.
Sandbox is fully canned. Pivot card holds the tunnel lifecycle and the
proxied scan in one place.

## Backlog #27 — privesc suggester

`POST /api/privesc/suggest` runs ten read-only checks in the linPEAS
spirit — kernel, SUID binaries (GTFOBins-flagged), file caps, sudo
build, writable PATH dirs, writable cron files, NFS `no_root_squash`,
pivot groups, shadow readability, loaded modules — each with a fix
hint. No password, no writes, no payloads; every check degrades instead
of raising. Sandbox returns a canned checklist. Pivot Checklist button.

## Backlog #25 — false-positive tuner

`POST /api/engagement/{id}/vulns/suppress` hides a finding until a
chosen expiry (default 30 days) with a mandatory reason on record; a
`vuln_suppressions` table keeps the audit trail (actor, timestamps) and
expired rows go inert automatically while staying visible for review.
`DELETE .../vulns/suppress` lifts early; `GET .../vulns/effective`
annotates findings with live suppressions (`hide_suppressed` filters).
Out-of-scope hosts are refused, never recorded. Recon card with reason
field + suppression list.

## Backlog #23 — KEV/EPSS enrichment

`h4k/data/kev.json` snapshots the live CISA catalog filtered to the 37
archive CVEs it actually hits, plus current FIRST EPSS scores — fetched
at implementation time, with catalog date and both source URLs stamped
in (no hand-written scores). `GET /api/kev/check` + `POST /api/kev/enrich`
serve the snapshot; `POST /api/kev/refresh` re-fetches and swaps the live
table, keeping the old one on any failure. Recon KEV card with opt-in
refresh. Unknown CVEs honestly report `kev:false, epss:null`.

## Backlog #20 — TLS cert inventory

`POST /api/tls/inventory` probes `host[:port]` targets and reports
expiry (expired high, <30 days medium), self-signed certs and weak
protocol/ciphers per host, ledgering each lead as a vuln with
`engagement_id` (scope-enforced). TLS card inventory row takes a
comma-separated list. Sandbox returns canned hosts.

## Backlog #18 — IPv6 discovery

`POST /api/net/ipv6/discover` reads the kernel NDP table (`ip -6 neigh`,
skipping FAILED/INCOMPLETE) and runs `nmap -6 -sn` only against an
explicit operator-supplied CIDR — never a blind v6 sweep. With
`engagement_id`, in-scope hosts are recorded as assets; out-of-scope
addresses are reported, never stored. Sandbox returns 3 canned hosts.
Discover Neighbors-v6 button + palette command.

## Backlog #16 — JARM/JA3 TLS fingerprints

`POST /api/tls/fingerprint` handshakes TLS ports with stdlib `ssl` and
records version/cipher/certificate per port, hashing the canonical
inventory into a stable exact-match fingerprint. Operator watchlists hit
high; self-signed/weak-proto/weak-cipher surface as labeled heuristic
leads. Scope honesty, D22-style: this is a handshake inventory, not a
raw-ClientHello JARM implementation — stdlib cannot emit the 10 crafted
probes, so no fuzzy similarity is claimed. Sandbox returns a canned
probe. Recon TLS card + palette command.

## Backlog #14 — PDF client report

`GET /api/session/report?fmt=pdf` downloads the assessment as a real PDF
(reportlab headings + tables, `Content-Disposition: attachment`), with
passwords masked like the loot vault — the MD/JSON exports keep full
detail. Report card Download PDF button fetches it as a blob. `reportlab`
joins `requirements.txt` and the image layer (pure-Python, no system
deps); a bare environment fails loudly instead of shipping an empty file.

## Backlog #12 — loot vault with redaction

`GET /api/engagement/{id}/vault` rolls verified credentials, captured
flags and enumerated shares into one loot view that is masked by default
(passwords → `••••` hints, flags → wrapper shape only) and unmasks only
with explicit `reveal=true`; `GET .../vault/export` downloads the masked
(or, if asked, unmasked) `.md`/`.json` for handoff. Score vault card is
masked-first with a reveal checkbox and MD export. SSH key material stays
out: no collector banks it, so the vault never fabricates it.

## Backlog #10 — lockout-aware spray

Propagation replays now run under a spray policy: at most N attempts per
user per engagement (ledgered attempts count, default 25), an optional
jitter pause between logins (0 = off, skipped in sandbox), and lockout
signals recorded as `locked` so that user is never retried. Plan shows the
policy plus held-back counts; the Pivot ledger card exposes both knobs.
Unit + e2e `test_spray*` pin the cap, the ledger stop and the plan stats.

## Backlog #8 — Kerberos roast helpers

`POST /api/kerberos/asrep` (no-preauth users) and
`POST /api/kerberos/kerberoast` (service accounts, needs one valid login)
roast via impacket and return `$krb5asrep$`/`$krb5tgs$` hashes; `crack=true`
hands them to John as an explicit second step that never fires on its own.
Sandbox returns canned hashes (crack skipped). Pivot roast card + palette.

## Backlog #6 — NSE vuln suggest-and-run

`GET /api/nse/suggest?service=&product=` maps a fingerprinted service to
curated NSE scripts (16 services; unknown falls back to the generic
`vuln,default` sweep rather than inventing names). Running stays explicit
via `POST /api/nmap/nse` — nothing fires on suggest. Recon NSE card:
Suggest → per-script list → Run. Sandbox refuses to spawn nmap and says so.

## Backlog #4 — credential hygiene report

`GET /api/engagement/{id}/hygiene` summarizes the hygiene of already-verified
credentials: reuse (same pair on N hosts), weak (short/common heuristic,
labeled as such), default (pair ships in `data/creds.json`), plus a 0–100
score. Read-only — nothing is sprayed. Pivot ledger card button + findings;
sandbox-seeded estate shows reuse on its first load.

## Backlog #2 — Nuclei offline bundle + ledger

`POST /api/nuclei` (opt-in) now takes `offline` (bundled templates only, no
network fetch) and `engagement_id` (findings recorded as vulns, scope-checked,
out-of-scope hosts reported not stored). `GET /api/nuclei/templates` exposes
the 3-template bundle (`h4k/data/nuclei-templates/`: log4shell, struts-rce,
bluekeep). Sandbox mode returns a canned critical finding so the Recon card +
palette button and e2e stay hermetic.

## Backlog #1 — interactive attack-graph canvas

`POST /api/nuclei` (opt-in) now takes `offline` (bundled templates only, no
network fetch) and `engagement_id` (findings recorded as vulns, scope-checked,
out-of-scope hosts reported not stored). `GET /api/nuclei/templates` exposes
the 3-template bundle (`h4k/data/nuclei-templates/`: log4shell, struts-rce,
bluekeep). Sandbox mode returns a canned critical finding so the Recon card +
palette button and e2e stay hermetic.

`GET /api/engagement/{id}/graph/canvas` (`services/graph_canvas.py`) lays out
the store's asset graph deterministically (hosts on a circle, service
`host:port` endpoints on a ring around their parent, verified
credential/pivot labels on a top row) so the Score tab can render a stable
SVG without a physics engine. The canvas supports drag-pan, wheel-zoom,
click-for-details and one-click PNG export; same input graph always yields
identical coordinates, keeping e2e stable. Read-only like `graph` itself.
