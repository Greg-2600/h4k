# Service reference

One line per service: what it does, what it touches, and how to test it.

> The canonical list also lives in `AGENTS.md`; this page adds the *test seam*
> for each module, which is what you actually need when changing code.

---

## Recon & scanning

| module | does | side effects | test seam |
|---|---|---|---|
| `scan_pipeline.py` | orchestrates recon → fingerprint → scan → creds → attack | shells out, writes `neighbors.db` | monkeypatch `subprocess.run` (`no_subprocess` fixture) |
| `modes.py` | stealth / tor / overt parameters | none | pure functions |
| `discovery.py` | ARP / IPv6 / SNMP neighbours | shells out (`arp-scan`, `ping6`, `snmpwalk`) | `NeighborFinder.discover`; sandbox mode returns a fixed estate |
| fingerprint (`routers/scan.py` + `toolkit.py` nmap) | service/version/OS detection (`-sS -sV -O`) | shells out (`nmap`) | stub `ToolkitRunner.run_tool`; results merged into `neighbors.db` |
| `cve_lookup.py` | banner-aware CVE matching | refreshes `cves.json` (network) | set `H4K_REFRESH_CVE=0`; `CveDb.refresh()` is monkeypatched in tests |
| `creds.py` | default-credential matching | none | pure |
| `vulnleads.py` | EOL / old-version heuristics | none | pure |
| `security.py` | traceroute + exposure posture | shells out (`traceroute`) | stub the subprocess |
| `version_detector.py` | version parsing/normalization | none | pure |
| `next_move.py` | ranked next-action recommendation | reads the store | pure over store data |
| `capabilities.py` | tool/MSF/storage readiness report | version probes | `tool_report()` with stubbed `shutil.which` |

## Attack surface

| module | does | side effects | test seam |
|---|---|---|---|
| `attack.py` | opt-in Metasploit exploit execution | real exploitation | `AttackService.run` with a `FakeMsf` |
| `toolkit.py` | opt-in hydra/nikto/sqlmap/… | shells out | `ToolkitRunner.run_tool`; sandbox mode returns canned output |
| `propagate.py` | replays **verified** credentials | real logins | `PropagationService` + `FakeMsf` |
| `engagement.py` | scope-enforced persistent store | SQLite writes | `EngagementStore(tmp_path/"e.db")` |

## Analysis

| module | does | side effects | test seam |
|---|---|---|---|
| `fuzzer.py` | signal-guided HTTP mutation | HTTP requests to the target | inject a fake HTTP client |
| `crashes.py` | crash fingerprinting + dedup | none | pure |
| `triage.py` | crash → bug class + CWE | none | pure |
| `sanitizer.py` | ASan/UBSan flags + trace parsing | none | pure |
| `sast.py` / `semgrep.py` | regex heuristics + real Semgrep | shells out (`semgrep`) | `semgrep` binary may be absent → heuristics still run |
| `sca.py` | SBOM (trivy) + osv-scanner + secrets/licenses | shells out | needs a lockfile to find CVEs |
| `merged_report.py` | one-click consolidated report | none | pure |
| `ingest.py` | zip/tar/git ingest (zip-slip safe) | writes to a temp dir | `tmp_path` |
| `ossfuzz.py` | build + asan + fuzz auto-runner | shells out, downloads | needs a toolchain |
| `rules.py` | custom rule library | JSON file | `tmp_path` |

## AI

| module | does | side effects | test seam |
|---|---|---|---|
| `ai.py` | provider abstraction (Ollama / OpenAI-compatible) | HTTP to the model | monkeypatch the client |
| `ai_loop.py` | root cause → minimal trigger → patch → verify | HTTP + subprocess | monkeypatch both |

## Reporting & engagement

| module | does | side effects | test seam |
|---|---|---|---|
| `report.py` | scoring + recommendations + report model | none | pure |
| `attack_paths.py` | crown jewels → scored paths | reads the store | `compute_attack_paths(store, id)` |
| `flag_paths.py` | foothold → captured-flag chains | reads the store + flag store | `compute_flag_paths(store, id)` |
| `attck.py` | ATT&CK mapping + detection guidance | reads the store | `enrich_engagement(store, id)` |
| `merged_report.py` | merge scan+SAST+SCA+fuzz+triage+watch | none | pure |
| `watch.py` | canonicalize + diff estate snapshots | none | pure (`canonicalize`, `diff_snapshots`) |
| `blue_team.py` | Navigator layer + Sigma bundle + defender writeup | none | pure (canned enriched engagement) |
| `supervisor.py` | liveness probes + restarts w/ per-service backoff | local subprocess only | injectable clock + fake specs |

## CTF / lab

| module | does |
|---|---|
| `zap.py` | OWASP ZAP headless scans via REST |
| `john.py` | John the Ripper hash cracking |
| `aircrack.py` | wireless assessment (monitor/capture/crack) |
| `tshark.py` | pcap/live capture + flow/credential extraction |
| `container_escape.py` | escape **detection** (read-only) + explicit helpers |
| `lateral.py` | route map, SSH/SOCKS + chisel tunnels, SMB sessions |
| `db_interrogate.py` | enumerate local APIs/DBs for flag-shaped secrets |
| `tls_lab.py` | local CA + loopback HTTPS proxy for the fuzzer |
| `firetv.py` | Fire TV / Android TV via adb (recon, pair, shell, apps, pull…) |
| `container_fuzz.py` | Docker/kubelet/gRPC/HTTP surface fuzzing (job-based) |
| `ad_tools.py` | BloodHound / mitm6 / Responder wrappers |
| `nuclei.py` / `sqlmap.py` / `ollama.py` | template scans / SQLi testing / Ollama exploit checks |
| `privesc.py` | local-root awareness (docker-group, userns, SUID/caps audit) |
| `flags.py` | flag-shaped secret ledger + detection |
| `auth.py` | opt-in API-key authentication |
| `auto_scan.py` | passive boot-time subnet map |
| `passive_sniff.py` / `sniffer.py` | packet capture + flow/credential analysis |
| `sbom.py` / `source_fetcher.py` / `vuln_analyzer.py` | SBOM map / repo fetching / finding normalization |

## Infrastructure

| module | does | side effects | test seam |
|---|---|---|---|
| `msfrpc.py` | thin `pymetasploit3` wrapper | talks to `msfrpcd` | `FakeMsf`; `MsfClient.execute` is the seam |
| `sandbox.py` | deterministic stand-ins for nmap/hydra/MSF | **none** | `enabled()` / `tool_result()` / `seed_engagement()` |
| `updater.py` | periodic tool/CVE/rule refresh | network, installs | monkeypatch `_which` and the state file |
| `rules.py` | custom rule persistence | JSON | `tmp_path` |

---

## Adding a service

1. Put it in `h4k/api/services/<name>.py`.
2. **No HTTP imports** in a service. Take plain data, return plain data.
3. Isolate every external call behind one function so tests can replace it.
4. Add it to `AGENTS.md`'s service table and to this page.
5. Write unit tests that never touch the network.
