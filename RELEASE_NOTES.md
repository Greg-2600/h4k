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

### 2.6 Platform / UX

- **Terminal-style pipeline UI** (zsh/opencode aesthetic): status bar, live
  console, sticky target banner, and a three-stage workflow — **Recon →
  Source & Supply → Fix** — with a primary CTA per stage, collapsible
  secondary/lab tools, and a consolidated results region.
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
GET   /api/jobs/{id}                  status · progress · log · report
GET   /api/report/{id}
POST  /api/scan/{id}/abort
GET   /api/export/{id}?fmt=json|md
GET   /api/neighbors                   ARP sweep
POST  /api/attack                      opt-in Metasploit exploit
POST  /api/deepattack                  opt-in toolkit sweep (hydra/nikto/...)
POST  /api/vulnleads                   EOL/beta/old version leads
POST  /api/fuzz + /api/fuzz/{id}        lab fuzzer (own target)
POST  /api/source/scan                 clone+SAST (git URL)
POST  /api/source/scan/upload          upload+SAST (zip/tar/tgz)
POST  /api/source/exploit              PoC skeleton
POST  /api/source/exploit/download     PoC as file
POST  /api/source/sca · GET /sca/git   SBOM + SCA/CVEs
POST  /api/source/triage · .../minimize
POST  /api/source/ai                   AI root-cause + patch (Ollama/OpenAI)
POST  /api/source/rules/test           custom Semgrep rule validation
GET   /api/health
```

---

## 6 · Quality

- **127 unit/API tests**, no live daemon required (mocked MSF backend).
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

---

## 8 · Layout

```
Dockerfile · docker-compose.yml     platform image (+ vulnlab service)
api/
  main.py · schemas.py · app_state.py
  routers/  scan.py · source.py
  services/ msfrpc, scan_pipeline, modes, report, cve_lookup, creds,
            attack, toolkit, discovery, security, fuzzer, vulnleads,
            sast, semgrep, sca, triage, ai, ingest
data/       cves.json · creds.json · users/passwords/web-words lists
web/        terminal UI (html/css/js)
scripts/    DNS recon bash tools
vulnlab/    intentionally-vulnerable fuzzing target + harnesses
tests/      unit + API tests
```

**h4k**, out.
