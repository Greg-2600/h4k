# h4k — current project state (read this first in a new session)

> Last updated: 2026-09-17 · branch `main` on `git`

This file is a **snapshot of the live project** so a fresh session can pick up
immediately: what's running, what's committed, how to bring it up, and what's on
the immediate horizon.

---

## 1 · Quick reality check

| Item | Status |
|---|---|
| Git branch | `main` |
| Tests | **155 passing** (offline, mocked Metasploit) |
| Linters | black · ruff · isort · flake8 · mypy · bandit all green · pylint ~9.88 |
| Container | **`h4k`** running, host-networking, UI on `http://127.0.0.1:3137` |
| Local LLM | Ollama reachable at `127.0.0.1:11434` (30 models); default `qwen2.5:latest` |

**The most common gotcha:** `docker build` does **not** leave the container
running — you must `docker run` (or `docker compose up`). If the UI is unreachable,
just restart the container (see §3).

---

## 2 · What h4k is

A self-contained, **containerized offensive-security analysis platform** for
authorized lab work. It drives **Metasploit** over msfrpcd (MessagePack-RPC),
and layers modern analysis on top:

- **Host recon & scan** — 3 OPSEC modes (stealth / Tor / overt), `-sV -O` service
  + OS detection, banner capture, ARP neighbors, DNS/PTR, posture heuristic.
- **Vulnerability** — curated local CVE archive (banner-aware), EOL/version
  leads, default-cred archive, ranked recommendations.
- **Source analysis (SAST)** — upload `.zip/.tar/.tar.gz` or clone a git URL →
  Semgrep (offline mode) + regex heuristics; custom-rule library.
- **Supply-chain (SCA/SBOM)** — CycloneDX SBOM (trivy) + osv-scanner → known CVEs
  + secret scan + dependency-graph supply-chain map.
- **Fuzzing** — black-box HTTP fuzz + a bundled coverage-guided lab
  (libFuzzer / AFL++ / ASan) in the separate `vulnlab` container.
- **Triage & PoC** — crash → bug-class/CWE → minimized repro → patch direction →
  PoC/disclosure skeleton (downloadable).
- **AI assist** — local **Ollama** root-cause + patch; exploit-first full-loop
  (crash→minimal trigger confirming the vuln→patch→verify); model picker in UI.
- **Active toolkit (opt-in)** — Metasploit exploits, hydra/ncrack/john,
  sqlmap/nikto/gobuster/ffuf/wpscan, smbmap/smbclient, impacket
  (secretsdump/GetNPUsers/kerberoast), ldapsearch/rpcclient, chisel/sshuttle pivot.
- **Network-layer (opt-in)** — tcpdump sniff, arp-scan, bettercap MITM,
  aircrack-ng WiFi scan/capture.
- **Auto-update** — periodic refresh of semgrep/osv-scanner/trivy + CVE/creds.

**Every aggressive action is off by default and opt-in.** This is a lab tool for
systems you own or have written permission to test.

The web UI is organized as a three-stage pipeline — **Recon → Source & Supply →
Fix** — with a sticky target banner and a primary CTA per stage; secondary / lab
tools are tucked under collapsible "more tools" disclosures. The Fix stage hosts
the OSS-Fuzz auto-run → crash minimize → AI exploit + fix (trigger → patch →
verify) demo flow. A bottom
**consolidated report** panel merges the session's scan/SAST/SCA/fuzz results and
downloads a single `.md`/`.json` assessment.

---

## 3 · Bring it up / run

```sh
# build the platform image
cd h4k && docker build -t h4k .

# run it
docker run -d --name h4k --network host \
  -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks -e H4K_REFRESH_CVE=0 \
  -e H4K_AUTO_UPDATE=1 -e H4K_UPDATE_INTERVAL=21600 \
  -e H4K_AI_PROVIDER=ollama -e OLLAMA_BASE_URL=http://127.0.0.1:11434 -e H4K_AI_MODEL=qwen2.5:latest \
  h4k

# UI -> http://127.0.0.1:3137
```

Compose (platform + vulnlab + optional Ollama sidecar):

```sh
cd h4k && docker compose up --build
docker compose --profile llm up   # adds Ollama sidecar on 127.0.0.1:11435
```

Sanity checks:

```sh
curl -s http://127.0.0.1:3137/api/health        # msf:"True", jobs:0
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3137/   # 200
```

---

## 4 · Container hygiene (this host)

Only **`h4k`** belongs to this project. The rest of the running containers
(`2b-*`, `oobir_*`, `zhc3-*`, `svc-main`, `ollama`, etc.) are **other
projects** — leave them alone unless you're explicitly asked.

There are also several **stale, exited containers** with auto-generated names
(`stale-container-a`, `stale-container-b`, `stale-container-c`, etc.). Most are
intermediate images from earlier builds and are **not** this repo's. Do not bulk
`docker system prune` here — it could remove another project's named containers.
Clean up an h4k container only by exact name.

---

## 5 · Local dev / test loop (host, uses `.venv`)

```sh
source .venv/bin/activate        # or .venv/bin/<tool>
make fmt      # black + isort
make fix      # ruff --fix
make lint     # black ruff isort flake8 mypy pylint bandit
make test     # pytest   (155)
make coverage # pytest --cov
```

Note: `pytest` runs offline. The API tests use a mocked Metasploit backend — no
live daemon needed. Tests that reach the network are monkeypatched (e.g.
`test_updater`, `test_ai`).

---

## 6 · API surface (FastAPI, under `/api`)

**Host / scan** — `POST /scan`, `GET /jobs/{id}`, `GET /report/{id}`,
`POST /scan/{id}/abort`, `GET /export/{id}?fmt=json|md`, `GET /neighbors`,
`POST /attack`, `GET /attack/{job_id}`, `POST /deepattack`, `GET /vulnleads`,
`POST /fuzz`, `GET /fuzz/{id}`, `POST /fuzz/minimize`.

**Source (SAST/SCA/AI/triage)** — `POST /source/scan`,
`POST /source/scan/upload`, `POST /source/exploit`,
`POST /source/exploit/download`, `POST /source/sca`,
`GET /source/sca/git`, `GET /source/sca/sbom`, `GET /source/sca/map`,
`POST /source/triage`, `POST /source/triage/minimize`,
`POST /source/ai`, `POST /source/ai/loop`, `GET /source/ai/models`,
`POST /source/rules/test`, `GET /source/rules`, `POST /source/rules/save`,
`DELETE /source/rules/{id}`, `POST /source/rules/run`,
`POST /source/report/merge`, `POST|GET /source/report/md`,
`POST /source/ossfuzz`.

**Network layer (opt-in)** — `GET /net/interfaces`, `POST /net/sniff`,
`POST /net/arp`, `POST /net/mitm`, `POST /net/wifi/scan`,
`POST /net/wifi/capture`.

**Updater / health** — `POST /update`, `GET /update/last`,
`GET /update/should`, `GET /health`.

---

## 7 · Services (api/services/) — quick map

| module | purpose |
|--------|---------|
| `msfrpc.py` | pymetasploit3 wrapper over msfrpcd |
| `scan_pipeline.py` | orchestrator: recon→fingerprint→scan→creds→attack |
| `modes.py` | stealth/tor/overt nmap + Proxies config |
| `report.py` | scoring + recommendations + report models |
| `cve_lookup.py`, `creds.py` | curated offline archives |
| `attack.py`, `toolkit.py` | opt-in MSF exploits + non-MS toolkit |
| `discovery.py`, `security.py` | ARP neighbors, posture heuristic |
| `fuzzer.py` | black-box HTTP fuzz + sanitizer-trace parse + minimize |
| `vulnleads.py` | EOL/beta flagging |
| `sast.py`, `semgrep.py` | regex (+ offline Semgrep) SAST + custom rules |
| `sca.py`, `sbom.py` | supply-chain CVEs + dependency-graph map |
| `triage.py` | crash→bug-class/CWE/patch/minimize |
| `ai.py`, `ai_loop.py` | Ollama root-cause + patch + full-loop |
| `rules.py` | custom-rule library |
| `merged_report.py` | one-click consolidate export |
| `ossfuzz.py` | OSS-Fuzz-style build+asan+fuzz runner |
| `ingest.py` | source ingest (zip/tar/git), zip-slip-safe |
| `updater.py` | periodic tool/data refresh |
| `sniffer.py` | tcpdump/arp/bettercap/aircrack opt-in lab tooling |

---

## 8 · Known notes / honest limits

- **SCA needs a lockfile** to surface CVEs; fresh clones without one return no
  findings by design. Demo fixture: `demos/sca-demo/` (pins vulnerable
  `lodash 4.17.20`).
- **SAST/Semgrep flag candidates, not proven bugs** — analyst confirms.
- **Posture** is a heuristic, **AI output is unvalidated** (verify on your own).
- **network-layer / WiFi** need monitor-mode NIC, root, or NET_ADMIN/NET_RAW in
  the container; the code degrades gracefully if not available.
- **netexec/crackmapexec** was **not** added — no installable PyPI/apt package.

---

## 9 · Docs to keep in sync

- `AGENTS.md` — technical context for agents (services, gotchas, dev loop).
- `RELEASE_NOTES.md` — feature + design decisions.
- `ROADMAP.md` — prioritized future work (Tier 1-3 + infra).
- `README.md` (root) — GitHub landing page + architecture diagram + demo GIF.
- `h4k/README.md` — PHRACK ezine; `vulnlab/README.md` — fuzz lab guide.

When you change behavior (new services, endpoints, features, tools), update
`AGENTS.md`, `RELEASE_NOTES.md`, `ROADMAP.md` accordingly so the next session
stays accurate.
