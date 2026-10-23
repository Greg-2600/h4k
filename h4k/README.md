```
                 _____
                |  .  |  ...   h4k :: intrusion-suite :: 3137
                |___.__|
     ,===.   ___
     |===|  |   |    .-'''''-.
     |===|  |   |  .'         '.
     |   |  |   |.'             '.
     |   |__|   |/   RECON-AD-   \
     |        __/    VISORY-SUITE\
    _|======='        _____________\
   /                        \        \
  /     H H H   HHH HH  H    '--------'
 /                           ||  ||
```

```
 HHHHHHHH    AAAA    KKK   KKK
 H          A    A   KKK  KK
 HHHHHHHH  AAAAAAAA  KKKK
 H         A      A  KKK  KK
 H         A      A  KKK   KKK
```

## h4k :: Intrusion-Suite

```
+----------------------------------------------------------------------+
|  PHRACK 14 (REVISED) -- a window into the wires
+----------------------------------------------------------------------+
|  h4k : a fast, local, browser-driven recon-and-advise suite built    |
|        atop the Metasploit Framework RPC daemon.                      |
|                                                                      |
|  It does the boring part of a pen-test for you: point it at a box,   |
|  pick your noise floor, and let it enumerate, scan, cross-reference   |
|  the local CVE archive, and tell you *where* to look next.           |
+----------------------------------------------------------------------+
```

You are reading the **h4k** manifest. This is a school cybersecurity capstone —
a self-contained, containerized lab tool that drives Metasploit's own RPC
interface so it never has to reimplement the framework. It answers, for an
authorized lab target:

  *What is out there?  (recon)
  *What is broken?     (scan + local CVE cross-ref)
  *Where do I hit next?(prioritized recommendations)

It also analyzes the **software you actually run**: upload/clone source and get
SAST (Semgrep + heuristics), SBOM/SCA (supply-chain CVEs), crash triage, PoC
skeletons, and AI-assisted root-cause & patching (local Ollama) — on top of a
coverage-guided fuzzing lab.

> Full inventory & design decisions: **`RELEASE_NOTES.md`· `ROADMAP.md`**.

Every aggressive action — default-credential testing, Metasploit exploitation,
and the deep toolkit (brute force, web vuln, SQLi) sweep — is **opt-in and off
by default**. A plain scan only reconnoiters, fingerprints, and advises. You
flip the switches, on your own lab range, on your own terms.

```
+----------------------------------------------------------------------+
+  AUTHORIZATION IS NOT OPTIONAL.                                       +
+  Run this suite ONLY against systems you own or hold written         +
+  approval to test. A proxy chain, Tor circuit, or fancy banner does   +
+  not make unauthorized intrusion lawful.                              +
+----------------------------------------------------------------------+
```

---

## 1 · The lay of the land

```
+----------+    HTTP/JSON    +--------------+   MessagePack-RPC   +-----------------+
|  browser | --------------> |   FastAPI    | -------------------> |   msfrpcd       |
|  terminal|   (web UI on   |   (api/)     |    port 3137:55553   |   Metasploit     |
|    TUI   |   0.0.0.0:3137)|              |                      |   Framework DB  |
+----------+                +--------------+                      +-----------------+
                                     | subprocess (bash tools)
                                     v
                             DNS recon: dns_dumpster,
                             sub_domain_lookup, reverse_dns
```

Three moving parts, one container:

| part        | role                                                       |
|-------------|------------------------------------------------------------|
| `web/`      | term-style UI: status bar, console, operation & report     |
| `api/`      | FastAPI + job runner; talks to Metasploit's MessagePack RPC |
| `data/`     | curated CVE archive, matched offline against findings      |

No Metasploit GUI, no Pro license, no cloud: every byte flies over your own
loopback to a local `msfrpcd`.

---

## 2 · Operating modes — choose your noise floor

The same suite, three acoustic signatures:

| mode      | trick                                                  |
|-----------|--------------------------------------------------------|
| `stealth` | `-sT -T2 --top-ports 100`, no OS detect, low retries.   |
| `tor`     | `Proxies socks5:127.0.0.1:9050` + wrapped in proxychains.|
| `overt`   | `-sS -T4 -sV -O --top-ports 500 --min-rate 1000`. Fast. |

Metasploit's native `Proxies` datastore option routes module outbound traffic
through Tor's SOCKS listener — no wrapper re-jiggering needed for the modules.

---

## 3 · The pipeline, stage by stage

```
target  ─► normalize (ip / cidr / hostname)
   │
   ├─ [DNS recon]      dns_dumpster · sub_domain_lookup · dnstracer · dig       (domain)
   ├─ [reverse DNS]   PTR lookups on every discovered IP (dig @public resolver)
   ├─ [port scan]      db_nmap → hosts/services into the MSF database    (-sV -O)
   ├─ [fingerprint]    nmap banners + whatweb → make/model/os/technology
   ├─ [traceroute]     path/authority mapping when present
   ├─ [aux scanners]  scanner/<svc>_version · smb_enumshares · netbios · ldap ·
   │                  msrpc/dcerpc · smb_enum_users · smb_login         (jobs awaited)
   ├─ [collect]        services + vulns from the DB, scoped to target
   ├─ [posture]        traceroute + exposure → security level/score/confidence
   ├─ [opt-in creds]   default/known creds vs matched services (verify/session)
   ├─ [opt-in attack]  Metasploit exploit modules vs fingerprinted services
   └─ [advise]         local CVE archive match  →  ranked recommendations
```

### Fingerprinting & default credentials

Two sources beyond the stock port scan:

- **Fingerprint** — host make/model/OS/technology is derived from nmap service
  banners and, for web services, `whatweb` output (added to the image).
- **Default credentials (opt-in)** — a curated `data/creds.json` ships ~30
  universal pairs (`admin/admin`, `root/toor`, `pi/raspberry`, ...) plus make/model
  entries for home routers (Linksys, Netgear, TP-Link, D-Link, Belkin, ZyXEL,
  ASUS, MikroTik, Ubiquiti, OpenWrt, pfSense, Arris/Surfboard, DrayTek),
  Raspberry Pi OS, Apple macOS / Windows, IP cams/HVAC, and NAS boxes.

Credential testing is **off by default**. It only runs when a scan explicitly
sets `try_default_creds` (UI checkbox / API flag). When enabled, login modules
run with `CreateSession` set per the operator's choice (verify-only by default,
session-open if explicitly requested), so the tool still **advises** unless you
tell it to open a session — on an authorized lab target only.

Every finding is scoped back to the original target so you are never looking at
a neighbor's machine by accident.

### The local CVE archive

`data/cves.json` is a hand-curated set (~30 entries) of high-signal CVEs —
EternalBlue, BlueKeep, PrintNightmare, Heartbleed, Shellshock, Zerologon,
Log4Shell, SMBGhost, the OpenSSH enumeration family, and so on. Each carries:

```json
{
  "id": "CVE-2017-0144",
  "aliases": ["MS17-010", "EternalBlue"],
  "product": "smb",
  "service": ["smb", "microsoft-ds", "netbios-ssn"],
  "cvss": 9.8,
  "severity": "CRITICAL",
  "title": "EternalBlue SMB Remote Code Execution",
  "description": "...",
  "msf_module": "exploit/windows/smb/ms17_010_eternalblue"
}
```

Matching is **banner-aware**: a CVE is only raised when the discovered
service's product token shows up in its banner (e.g. `OpenSSH 9.2p1` → SSH
enumeration CVEs; `postgresql` → the Postgres pair; a CherryPy box gets *no*
stray Log4Shell). At startup the archive tries one best-effort online refresh
and otherwise uses the bundled snapshot — it is fully operational offline.

### Hunting for newer bugs (0-day research, lab-only)

Two opt-in features move you from "known CVEs" toward finding **fresh**
vulnerabilities — genuinely a research method that must run against a service
you control:

- **Version-lead scan (`/api/vulnleads`)** — inspects service banners and flags
  **EOL / very old / beta / unusual** builds (OpenSSH, Apache, nginx, PHP, IIS,
  Tomcat, vsftpd...). An outdated version is a strong lead: it's a candidate for
  known-but-not-yet-patched *and* undisclosed bugs. This is where you start
  reading the source and diffing versions.
- **Lab fuzzer (`/api/fuzz`)** — mutates HTTP/network inputs (long headers,
  null bytes, format strings, overflow integers, URL oddities...) toward a
  service **you own** and watches for **anomalies**: server errors, stack
  traces, connection teardown, hangs, or the service going away. Each anomaly is
  recorded with the exact repro request and the mutation that caused it — the
  raw material for a real bug write-up and **responsible disclosure**.

> A 0-day is not a button. It is a *process*: fuzz your own running service,
> capture the anomaly, minimize the repro, prove root cause, then disclose
> responsibly (vendor first, advisory later). This tool automates the
> capture-and-triage part of that process — against systems you own.

---

## 4 · Build, run, point it

```sh
# build the container (installs Metasploit + deps; takes a few minutes)
docker build -t h4k .

# run it — --network host so the box can see your local lab hosts
docker run --rm --network host -p 3137:3137 \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
#   # AI triage, keyless via the opencode relay (start on the host first):
#   #   OPENCODE_MODEL=opencode/beam-free python3 h4k/scripts/opencode_relay.py
#   -e H4K_AI_PROVIDER=openai_compatible -e H4K_AI_KEYLESS=1 \
#   -e H4K_AI_URL=http://127.0.0.1:3777/v1/chat/completions \
#   -e H4K_AI_MODEL=opencode/beam-free \

  h4k

# open the terminal
#     http://localhost:3137
```

> **Heads-up:** `docker build` alone does **not** leave the container running.
> You must `docker run` (or `docker compose up`) to start the service.

`entrypoint.sh` orchestrates the boot: PostgreSQL up → `msfdb init` (as a
dedicated `msf` user) → Tor on `:9050` → `msfrpcd` on `:55553` → FastAPI
serving the UI on **0.0.0.0:3137**.

### First-run walkthrough (new users)

1. **Open `http://localhost:3137`.** You'll see a light dashboard: a target bar
   across the top, a four-item sidebar (Recon / Vulnerabilities / Exploit /
   Research), and a jobs + activity panel on the right.
2. **Scan a lab target** — enter an IP you own (e.g. a Raspberry Pi or a VM) in
   the **target** bar and press Enter (or keep mode on **overt** and hit **Run
   scan** in Recon). The activity panel streams progress, and the finished
   report opens **Vulnerabilities**: a severity-ordered triage list with tabs
   for findings, vulns, hosts, credentials, posture, version leads,
   fingerprints and notes.
3. **Find neighbors** — in Recon, click **Sweep for neighbors** to list
   IP/MAC/vendor on your local segment, and click **select** on any row to load
   it into the target bar.
4. **Act on a finding** — click any row in Vulnerabilities; it jumps to
   **Exploit** with the host, port, service and Metasploit module prefilled.
   Nothing is sent until you confirm.
5. **Analyze source** — in **Research**, paste a git URL (or upload a `.zip`)
   in the **Source** card and hit **Analyze**. Findings appear with
   severity/CWE, and triage below classifies them.
6. **Scan supply chain** — in Research, hit **Build SBOM** on a git URL **that
   has a committed lockfile** (see `demos/sca-demo/`) — you'll see known-CVE
   hits.
7. **Generate a PoC** — in the Research **Triage** list, hit **PoC** on a row to
   view or download the disclosure skeleton.
8. **Fuzz a lab target you own** — start the `vulnlab` container and aim
   Research's **Fuzzing** card at `127.0.0.1:8080` to watch anomaly detection.

> **Safety:** default-cred testing, Metasploit exploits, the deep toolkit, and
> the fuzzer are **all opt-in** and only for systems you own or have written
> permission to test.

### The REST surface

```
POST  /api/scan                      {target, mode, do_dns_recon, do_vuln_scan,
                                      try_default_creds, open_sessions, do_attack}
GET   /api/jobs/{id}                 status · progress · message · log · report
GET   /api/report/{id}               the full report
POST  /api/scan/{id}/abort           stop an in-progress scan
GET   /api/export/{id}?fmt=json|md    download report as json or markdown
GET   /api/neighbors?cidr=...         ARP neighbor sweep (arp-scan / msf / cache)
POST  /api/attack                    opt-in Metasploit exploit run
GET   /api/attack/{job_id}           poll attack results
POST  /api/deepattack                opt-in toolkit sweep (hydra/nikto/sqlmap/...)
GET   /api/deepattack/{id}           poll toolkit results
POST  /api/vulnleads                 flag EOL/beta/old service versions (research)
POST  /api/fuzz                      lab-only: fuzz a service you own (bug hunt)
GET   /api/fuzz/{job_id}             poll fuzz candidates
GET   /api/health                    msfrpcd reachability + job + cache counts
```

Scans are **cached for 5 minutes** per `target+mode`: re-scanning the same box
soon after returns the stored report instead of re-probing. Long scans can be
**aborted** mid-flight via the stop button; the job reports `aborted` with the
log kept.

### Drive it from the dashboard

The UI is four sections — **Recon**, **Vulnerabilities**, **Exploit** and
**Research** — with one target bar at the top that every action reads from. Type
a target and press Enter to scan it; the finished report lands you in
Vulnerabilities, where each row loads into the Exploit drawer with its module
pinned. Active actions (default credentials, exploitation, deep toolkit, CTF
tools) sit behind an explicit opt-in group and a confirmation that names the
target before anything is sent.

The console still accepts shortcuts, and the panes still have buttons:

```
h4k ➜ ~ scan 192.168.1.248 overt
h4k ➜ ~ status
h4k ➜ ~ clear
```

Buttons in the Recon pane: **stop** (abort in-progress scan), **export .json /
export .md** (download the report), **find neighbors (arp)** (sweep the local
segment and list IP/MAC/vendor), plus toggles for **default credentials** and
**active exploit attempts** — both opt-in, off by default, authorized scope
only. A separate **deep toolkit attack** button (with per-service checkboxes for
ssh/http/smb/dns) drives the non-Metasploit sweep.

---

## 5 · Linting, typing, security, tests

The repo is kept honest with a full static-analysis stack, wired through
`make` and `pyproject.toml`:

```
make setup      build a .venv with the dev toolchain
make fmt        black + isort in place
make fix        ruff --fix
make lint       black · ruff · isort · flake8 · mypy · pylint · bandit
make test       pytest (85 tests)
make coverage   pytest --cov  (70% gate)
```

Current status: **all green.**

- **ruff** — `E F W I B UP C4 SIM RUF ASYNC`, clean.
- **flake8** — clean (with `E402` scoped to `main.py` for the sys.path trick).
- **black / isort** — both `--check` clean at line-length 88.
- **mypy** — `Success: no issues found in 17 source files` (strict untyped-defs).
- **pylint** — rated **9.91/10**.
- **bandit** — no issues; deliberate subprocess/urlopen calls are audited and
  `# nosec`-annotated with rationale.
- **safety** — flags 5 advisories: 3 are toolchain-transitives (`setuptools`,
  `py`); the actionable one is `pymetasploit3 1.0.6`
  (**CVE-2026-5463**, command injection). It is pinned in the lock/requirements
  and the RPC calls it exposes are only fed internally-constructed arguments.

The tests live in `tests/` (99 passing) and cover the schemas, the OPSEC mode
matrix, the CVE matcher (including the CherryPy not-included guard), the
default-credential archive and attempt flow, recommendation scoring/ranking,
the pipeline's pure helpers, the attack/toolkit plan, and the HTTP API via a
mocked Metasploit backend — no live daemon needed to run them.

---

## 6 · Layout

```
Dockerfile          postgres + tor + proxychains + metasploit + api
entrypoint.sh       boot: pg → msfdb → tor → msfrpcd → uvicorn
requirements.txt    runtime deps
requirements-dev.txt lint/test toolchain            pyproject.toml  tool config
Makefile            fmt/fix/lint/test/coverage
api/
  main.py           FastAPI app (serves UI + API)
  schemas.py        pydantic models
  routers/scan.py   REST endpoints + job runner
  services/
    msfrpc.py       thin pymetasploit3 wrapper
    scan_pipeline.py orchestrator: recon → fingerprint → scan → creds → attack
    attack.py       opt-in Metasploit exploit execution + module mapping
    toolkit.py      opt-in non-Metasploit tool sweep (hydra/nikto/sqlmap/...)
    discovery.py    ARP neighbor discovery (arp-scan / arp cache / msf)
    security.py     traceroute + exposure → security posture heuristic
    modes.py        stealth / tor / overt config
    report.py       scoring + recommendations
    cve_lookup.py   offline archive + matching + refresh
    creds.py        default-credential archive matching
    fuzzer.py       lab fuzzer → anomaly/bug-candidate triage
    vulnleads.py    EOL/beta/old version flagging
data/cves.json      curated CVE archive
data/creds.json     default-credential archive (opt-in use)
data/users.txt      deep-toolkit username list
data/passwords.txt  deep-toolkit password list
web/                term-style UI (html/css/js) + phrack ezine README view
scripts/            DNS recon bash tools (from the author's toolbox)
tests/              99 unit + API tests
```

---

## 7 · The fine print

- **Exploitation is opt-in and off by default.** The suite never auto-attacks on
  a normal scan. Only when **active exploit attempts** is toggled (or `/api/attack`
  is called) does it run Metasploit exploit modules, and only against services it
  fingerprinted on targets you authorize. Credential login attempts are likewise
  opt-in.
- **OPSEC is a tool, not a license.** Stealth and Tor keep your *own* footprint
  quiet in a sanctioned lab; they do not make an unauthorized scan permissible.
- This is a **learning weapon**. Learn the trade, not just the keystrokes: read
  the module names it suggests, understand each CVE's root cause, and defend
  against these same patterns on your own systems.

---

## 8 · For the class — quick start & ethics

This is a **school capstone demonstration**, not a real-world weapon. It runs
against your own lab (VMs, a test router, metasploitable boxes). Presenting it
well is about the *process*: enumeration, fingerprinting, CVE cross-reference,
and responsible reporting.

### A safe demo walkthrough (10 minutes)

1. Launch the container, open `http://localhost:3137`.
2. In the operation pane enter a **lab target you control** (e.g. a Raspberry Pi
   with SSH, a Linux VM, or a Metasploitable instance you provisioned).
   Keep the mode on **overt**.
3. Click **find neighbors (arp)** — show it maps your local segment to vendor
   (Raspberry Pi, VMware, Netgear, ...).
4. Click **run scan** (leave the two toggles off). Walk the report tabs:
   hosts → fingerprint → vulns (CVE cross-refs) → security posture → recs.
5. To demo credential testing, tick **try default credentials** and re-run a
   scan — it will enumerate default/known pairs on your lab box.
6. Export to `.md` / `.json` to show the clean written report.

### Ethics you should say out loud in the demo

- **You can only run this against systems you own or have written permission to
  test.** A proxy or Tor chain never makes a scan legal.
- **Nothing here is "hacking for the sake of it."** The point is assessment:
  find the exposure, understand the CVE, and write a defensible recommendation.
- **The aggressive knobs (creds / attacks / deep toolkit) are off by default**
  and are disabled in the UI until you explicitly switch them on — that is a
  feature, not a limitation.

### Suggested lab targets (all free, all authorized)

- **Metasploitable 2/3** — intentionally vulnerable Linux VM (ssh, samba, http,
  mysql...). The single best demo target.
- **A Raspberry Pi you own** with SSH enabled — shows fingerprinting + the
  `pi/raspberry` default-cred path.
- **An old home router** (Linksys, Netgear, TP-Link...) you no longer use —
  excellent for the make/model fingerprint + vendor cred entries.
- **A throwaway Linux VM** you provision yourself.

**h4k**, out.
