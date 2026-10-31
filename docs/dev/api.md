# API reference

Base URL: `http://localhost:3137`. Interactive docs: `/docs` (Swagger),
`/redoc`, raw schema `/openapi.json`. Everything is JSON. `tests/test_openapi.py`
asserts every registered route appears in the schema and every capability in
`/api/capabilities` maps to at least one endpoint.

Conventions:

* Errors are `{"detail": "..."}` with a meaningful status code.
* `POST` bodies are JSON unless noted (`multipart/form-data` for uploads).
* Aggressive endpoints require an active engagement scope.

---

## Health

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | `{status, msf:{reachable,version}, jobs, active_jobs, cache_entries}` |
| `GET` | `/api/capabilities` | What this instance can actually do: installed tools (+versions), Metasploit reachability **and database state**, data dir + wordlists, and `warnings` for anything that would silently fail (no Metasploit DB, missing nmap, sandbox mode). Cached for 60 s. |
| `GET` | `/api/session` | Session id, counts, active scope |
| `GET` | `/api/session/report?fmt=json\|md` | Full session writeup |

---

## Scan & recon

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scan` | `{target, mode, depth?, do_dns_recon?, do_vuln_scan?, try_default_creds?, open_sessions?, do_attack?}` → `{job_id, status}` |
| `GET` | `/api/jobs?active=true` | Job monitor across all job families |
| `GET` | `/api/jobs/{id}` | One job |
| `GET` | `/api/report/{id}` | Finished report |
| `POST` | `/api/scan/{id}/abort` | Cooperative abort |
| `GET` | `/api/export/{id}?fmt=json\|md` | Export |
| `GET` | `/api/neighbors` | ARP neighbours |
| `POST` | `/api/vulnleads` | EOL/old-version leads |
| `POST` | `/api/nuclei` | Nuclei templates (opt-in) |

### Modes and depth

`mode`: `stealth` | `tor` | `overt` · `depth`: `quick` | `standard` | `full`

---

## Attacks (all opt-in)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/attack` | One Metasploit module against one host. `options` passes module options through; `PAYLOAD`/`LHOST`/`LPORT` always pass (framework datastore keys, sent via raw `module.execute`). `"check_only": true` runs only the module's `check` → `vulnerable` / `likely_vulnerable` / `safe` / `unknown` / `check_failed`, no exploitation. Result is `success` **only** when a live session is confirmed — a launched job with no callback reports `failed: module ran as job N; no session opened`, never a phantom session id. From a container, reverse shells need a routable `LHOST` or (better) a `PAYLOAD` like `cmd/unix/bind_perl` that connects out |
| `POST` | `/api/passattack` | Hydra default-creds vs ssh/ftp/telnet/mysql/http-basic, plus `http-form` for HTML logins: `{"host","service":"http-form","form":{"path":"/index.php","user_field":"username","pass_field":"password","fail":"<failed-login-only marker>"}}`. The `fail` marker is operator-supplied — guessing it would fabricate results |
| `POST` | `/api/payload` | Render an msfvenom payload offline (no target touched): `{"payload":"php/bind_php","options":{"LPORT":4445},"format":"raw"}`. Generation is local; *using* it is the aggressive step |
| `GET` | `/api/attack/{id}` | Attack job state |
| `GET` | `/api/sessions` | Live msf sessions (`alive: true`) plus this session's recorded ones (`alive: false` when msfrpcd no longer holds them). Dead sessions are history, never presented as usable — re-enter via propagation or a fresh exploit |
| `POST` | `/api/deepattack` | Toolkit orchestration (hydra/nikto/sqlmap/…) |
| `POST` | `/api/nmap/nse` | NSE scripts |
| `POST` | `/api/nikto` | Standalone nikto web scan |
| `POST` | `/api/gobuster` | Standalone gobuster content discovery |
| `POST` | `/api/container_escape` | Escape **detection** (read-only) + explicit helpers |
| `POST` | `/api/lateral` | Routes, SSH/SOCKS tunnels, SMB sessions |
| `POST` | `/api/db_interrogate` | Enumerate local APIs/DBs for flag-shaped secrets |

---

## Autopilot (the walk)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/autopilot/start` | `{}` or `{"deep_web": true}` — **requires a scope** |
| `GET` | `/api/autopilot/status` | `{status, stage, progress, hosts, log}` |
| `POST` | `/api/autopilot/stop` | Cooperative stop |

---

## Engagement, scope, crown jewels

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/engagement` | `{name, scope[], notes?}` |
| `GET` | `/api/engagement` | List + summaries |
| `GET` | `/api/engagement/{id}` | One engagement |
| `DELETE` | `/api/engagement/{id}` | Delete (cascades) |
| `POST` | `/api/engagement/parse-scope` | `{text}` → validated CIDR list |
| `POST` | `/api/engagement/{id}/ingest` | Raw report or `{job_id}` → asset graph |
| `GET` | `/api/engagement/{id}/assets` | Hosts + services |
| `GET` | `/api/engagement/{id}/credentials` | Credentials + where each works |
| `GET` | `/api/engagement/{id}/graph` | Nodes + edges (pivot edges only where verified) |
| `POST` | `/api/session/scope` | `{engagement_id}` → activate; `null` → clear |
| `POST` | `/api/engagement/sandbox-seed` | Sandbox mode only: seeded demo engagement |

### Crown jewels & attack paths

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/engagement/{id}/crown-jewels` | `{host, label?, value?}` (value 1–100) |
| `GET` | `/api/engagement/{id}/crown-jewels` | List |
| `DELETE` | `/api/engagement/{id}/crown-jewels/{cj_id}` | Remove |
| `GET` | `/api/engagement/{id}/attack-paths` | `?crown_jewel_id=&max_depth=&limit=` — add `fmt=md` for a markdown writeup |
| `GET` | `/api/engagement/{id}/flag-paths` | Foothold → flag-host chains (one objective per flag host); `fmt=md` for a writeup |
| `GET` | `/api/engagement/{id}/export` | Portable snapshot (assets, services, credentials + access, vulns, attempts, crown jewels) |
| `POST` | `/api/engagement/{id}/import` | Merge a snapshot in; every host is scope-checked and out-of-scope hosts are reported |

`attack-paths` response:

```json
{
  "engagement_id": "b2ac8ca2ebfa",
  "crown_jewels": [{"id": "…", "host": "10.10.10.42", "label": "DC", "value": 90}],
  "paths": [
    {
      "crown_jewel_host": "10.10.10.42",
      "entry": "10.10.10.5",
      "nodes": ["10.10.10.5", "10.10.10.9", "10.10.10.42"],
      "edges": [{"type": "pivot", "user": "admin", "service": "ssh", "technique": "T1021"}],
      "hops": 2,
      "vulns": [{"host": "10.10.10.5", "name": "OpenSSH outdated", "severity": "high"}],
      "techniques": ["T1021"],
      "score": 131
    }
  ],
  "summary": {"crown_jewels": 1, "paths": 1, "best_score": 131, "footholds": 2}
}
```

### ATT&CK

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/engagement/{id}/attck` | Findings → techniques + detection guidance |
| `GET` | `/api/engagement/attck/techniques` | The technique catalog |

### Propagation

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/engagement/{id}/propagate/plan` | Dry run: blast radius, no network |
| `POST` | `/api/engagement/{id}/propagate` | `{open_sessions?, max_attempts?}` — replays **verified** creds only |

---

## Source analysis

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/source/scan` | SAST over a git URL |
| `POST` | `/api/source/scan/upload` | SAST over a `.zip/.tar/.tar.gz` (multipart) |
| `POST` | `/api/source/exploit` | PoC skeleton for disclosure |
| `POST` | `/api/source/sca` | SCA over a repo |
| `GET` | `/api/source/sca/sbom` | CycloneDX SBOM download |
| `POST` | `/api/source/triage` | Crash → bug class + CWE + patch direction |
| `POST` | `/api/source/triage/minimize` | Minimize a crash |
| `POST` | `/api/source/ai` | One-shot AI analysis |
| `POST` | `/api/source/ai/loop` | Full loop: root cause → trigger → patch → verify |
| `GET` | `/api/source/ai/models` | Available models |
| `POST` | `/api/source/rules/test` | Validate a custom Semgrep rule |
| `POST` | `/api/rules/save` · `/api/rules` · `/api/rules/run` | Custom rule library |
| `POST` | `/api/source/ossfuzz` | OSS-Fuzz-style build+asan+fuzz |
| `POST` | `/api/source/report/merge` · `GET /api/source/report/md` | Consolidated report |

---

## Fuzzing

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/fuzz` | Start a fuzzing run against a target **you own** |
| `GET` | `/api/fuzz/{id}` | Progress + crash candidates (deduped) |
| `POST` | `/api/fuzz/minimize` | Minimize a crash artifact |
| `POST` | `/api/container_surfaces` | Read-only inventory: docker/containerd/kubelet reachability |
| `POST` | `/api/container_fuzz` | Fuzz a surface you own (`docker\|kubelet\|grpc\|http`); job-based |
| `GET` | `/api/container_fuzz/{id}` | Job progress + candidates |

---

## Live network map (passive auto-scan)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/map` | Current passive map: hosts, services, vulns + auto-scan status |
| `GET` | `/api/map/status` | `{enabled, running, cidr, engagement_id, last_run, hosts_found, services_found, vulns_found, runs, error}` |
| `POST` | `/api/map/start` | Start the background auto-scan (force, even if `H4K_AUTO_SCAN=0`) |
| `POST` | `/api/map/stop` | Stop the background auto-scan |

## Flags + next move

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/engagement/{id}/flags` | All captured flags for this engagement |
| `POST` | `/api/engagement/{id}/flags` | `{value, host?, path?, method?, note?}` record a flag |
| `POST` | `/api/engagement/{id}/flags/detect` | `{text}` scan text for flag-shaped strings and record them |
| `DELETE` | `/api/engagement/{id}/flags/{flag_id}` | Remove a flag |
| `GET` | `/api/engagement/{id}/next-move` | Ranked 'next move' queue for this engagement |

The auto-scan starts automatically on boot when `H4K_AUTO_SCAN=1` (the
default). It detects the local subnet from the default route, creates a
default `auto-scan` engagement, and runs recon-only passes (no credential
testing, no exploitation) on a cadence (`H4K_AUTO_SCAN_INTERVAL`, default
3600 s). Set `H4K_AUTO_SCAN_CIDR` to override the detected subnet.

## CTF / lab toolkit (each explicitly opt-in)

| Method | Path |
|---|---|
| `POST` | `/api/zap` · `/api/john` · `/api/aircrack` · `/api/tshark/pcap` · `/api/tshark/live` |
| `POST` | `/api/nikto` · `/api/gobuster` · `/api/sqlmap` · `/api/nmap/nse` |
| `POST` | `/api/net/sniff` (quick capture) · `/api/net/sniff/deep` (capture + full analysis, folds into the engagement) · `/api/net/sniff/pcap` (analyse a pcap file) |
| `GET` | `/api/net/interfaces` |

---

## Updater

| Method | Path |
|---|---|
| `POST` | `/api/update` |
| `GET` | `/api/update/last` · `/api/update/should` |

---

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MSF_HOST` / `MSF_PORT` / `MSF_PASSWORD` | `127.0.0.1` / `55553` / `h4k_msf_rocks` | Metasploit RPC |
| `API_PORT` | `3137` | API port |
| `H4K_DATA_DIR` | `/opt/h4k/data` → `h4k/data` | Runtime data directory |
| `H4K_SANDBOX` | unset | `1` = deterministic offline mode |
| `H4K_RATE_LIMIT` | `600` | Requests/min/IP |
| `H4K_LOG_LEVEL` | `INFO` | Log level |
| `H4K_AUTO_UPDATE` / `H4K_UPDATE_INTERVAL` | `1` / `21600` | Background updater |
| `H4K_REFRESH_CVE` / `H4K_CVE_WEEKLY` | `1` | CVE archive refresh |
| `H4K_AI_PROVIDER` / `H4K_AI_URL` / `H4K_AI_KEY` / `H4K_AI_MODEL` | — | AI triage |
| `H4K_NET_IFACE` | auto | Force the discovery interface |
| `H4K_E2E` | unset | `1` enables the Selenium suite in pytest |
| `H4K_AUTO_SCAN` | `1` | `1` starts the passive auto-scan on boot |
| `H4K_AUTO_SCAN_CIDR` | auto | override the detected local subnet |
| `H4K_AUTO_SCAN_INTERVAL` | `3600` | seconds between auto-scan passes |
| `H4K_AUTO_SCAN_DEPTH` | `quick` | port breadth for the auto-scan (`quick`/`standard`/`full`) |
