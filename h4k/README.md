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

**This build stops short of auto-exploitation.** It advises; it does not fire
the shells. You pull the trigger, on your own lab range, on your own terms.

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
| `overt`   | `-sT/-sS -T4 -sV -O --top-ports 1000`. Fast and loud.    |

Metasploit's native `Proxies` datastore option routes module outbound traffic
through Tor's SOCKS listener — no wrapper re-jiggering needed for the modules.

---

## 3 · The pipeline, stage by stage

```
target  ─► normalize (ip / cidr / hostname)
   │
   ├─ [DNS recon]      dns_dumpster · sub_domain_lookup · reverse_dns  (optional)
   ├─ [port scan]      db_nmap  → hosts/services into the MSF database
   ├─ [aux scanners]   scanner/<svc>_version · smb_enumshares · ...     (jobs awaited)
   ├─ [collect]        services + vulns from the DB, scoped to target
   └─ [advise]         local CVE archive match  →  ranked recommendations
```

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

---

## 4 · Build, run, point it

```sh
# build the container (installs Metasploit + deps; takes a few minutes)
docker build -t h4k .

# run it — --network host so the box can see your local lab hosts
docker run --rm --network host -p 3137:3137 \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks h4k

# open the terminal
#     http://localhost:3137
```

`entrypoint.sh` orchestrates the boot: PostgreSQL up → `msfdb init` (as a
dedicated `msf` user) → Tor on `:9050` → `msfrpcd` on `:55553` → FastAPI
serving the UI on **0.0.0.0:3137**.

### The REST surface

```
POST  /api/scan                    {target, mode, do_dns_recon, do_vuln_scan}
GET   /api/jobs/{id}               status · progress · message · report
GET   /api/report/{id}             the full report
GET   /api/health                  msfrpcd reachability + job count
```

### Drive it from the terminal UI

```
h4k ➜ ~ scan 192.168.1.248 overt
h4k ➜ ~ status
h4k ➜ ~ clear
```

---

## 5 · Linting, typing, security, tests

The repo is kept honest with a full static-analysis stack, wired through
`make` and `pyproject.toml`:

```
make setup      build a .venv with the dev toolchain
make fmt        black + isort in place
make fix        ruff --fix
make lint       black · ruff · isort · flake8 · mypy · pylint · bandit
make test       pytest (47 tests)
make coverage   pytest --cov  (70% gate)
```

Current status: **all green.**

- **ruff** — `E F W I B UP C4 SIM RUF ASYNC`, clean.
- **flake8** — clean (with `E402` scoped to `main.py` for the sys.path trick).
- **black / isort** — both `--check` clean at line-length 88.
- **mypy** — `Success: no issues found in 12 source files` (strict untyped-defs).
- **pylint** — rated **9.90/10**.
- **bandit** — no issues; deliberate subprocess/urlopen calls are audited and
  `# nosec`-annotated with rationale.
- **safety** — flags 5 advisories: 3 are toolchain-transitives (`setuptools`,
  `py`); the actionable one is `pymetasploit3 1.0.6`
  (**CVE-2026-5463**, command injection). It is pinned in the lock/requirements
  and the RPC calls it exposes are only fed internally-constructed arguments.

The tests live in `tests/` and cover the schemas, the OPSEC mode matrix, the
CVE matcher (including the CherryPy not-included guard), recommendation
scoring/ranking, the pipeline's pure helpers, and the HTTP API via a mocked
Metasploit backend — no live daemon needed to run them.

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
    scan_pipeline.py orchestrator: recon → scan → analyze
    modes.py        stealth / tor / overt config
    report.py       scoring + recommendations
    cve_lookup.py   offline archive + matching + refresh
data/cves.json      curated CVE archive
web/                term-style UI (html/css/js)
scripts/            DNS recon bash tools (from the author's toolbox)
tests/              47 unit + API tests
```

---

## 7 · The fine print

- **No auto-exploitation.** The suite reports and recommends; you decide whether
  a lab target is in scope and whether to pursue a vector.
- **OPSEC is a tool, not a license.** Stealth and Tor keep your *own* footprint
  quiet in a sanctioned lab; they do not make an unauthorized scan permissible.
- This is a **learning weapon**. Learn the trade, not just the keystrokes: read
  the module names it suggests, understand each CVE's root cause, and defend
  against these same patterns on your own systems.

**h4k**, out.
