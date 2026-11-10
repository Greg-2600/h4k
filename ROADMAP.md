# h4k — Roadmap

Prioritized by **wow-factor for a class demo × real-world value × effort**. Each
item is a self-contained, live-demonstrable increment on the current release.

---

## Tier 1 — polish & airtightness (small effort, big payoff)

- [x] **Sanitizer-first everywhere** — surface ASan/UBSan flags in *every*
      finding (fuzz + SAST), not just line numbers, so each one shows a clean
      crash/error trace.
  (done: `services/sanitizer.py` is the single source of truth — build flags,
  `ASAN_OPTIONS`/`UBSAN_OPTIONS` for abort-on-first-error traces, a 17-class
  bug table, and per-finding `verify_plan` / `confirm_plan` blocks. SAST hits and
  fuzz candidates both carry it; `parse_sanitizer_trace` now classifies via the
  same table. Honest about limits: non-memory-safety classes say a sanitizer
  can't adjudicate them, and a black-box fuzz signal gets a replay recipe with
  candidate bug classes rather than a verdict. Bundled Semgrep rules gained
  `metadata.cwe` so their findings resolve a real CWE → real plan.)
- [x] **True crash minimization** — wrap libFuzzer `-minimize_crash=1` /
      `afl-tmin` behind `/api/fuzz` so a crash auto-reduces to the smallest
      repro, then feed it straight into triage. ("Here's the exact 12-byte
      trigger.")
  (real now: `libfuzzer_minimize` runs `-minimize_crash=1` in a clean temp cwd,
  reads back the smallest non-empty `minimized-from-<sha1>` artifact, ignores
  libFuzzer's non-zero exit (77 = crash reproduced, artifacts already written),
  and only claims a reduction when the result is genuinely smaller.
  Verified live against real libFuzzer: 4027 → 256 bytes (93.6%) on vulnlab B1,
  landing exactly on `BUF_SIZE`. The previous implementation returned the
  unmodified crash file on both its success and failure branch — it never
  reduced anything while reporting that it had.)
- [x] **Crash dedup — count bugs, not crashes** — fingerprint each crash by the
      sanitizer's error class + normalized top frames (ASLR addresses, line
      numbers, module offsets stripped), so thousands of crashing inputs
  collapse to the distinct bugs they actually are.
  (done: `services/crashes.py` + `CrashRegistry`. Live: 300 execs → 116 crashes
  → **2 distinct bugs**, exactly vulnlab's documented B1 stack-buffer-overflow
  and B2 format-param. Black-box signals stay unconfirmed leads. See D20.)
- [x] **Real mutation engine** — replace the fixed 13-payload probe list with a
      seeded, reproducible operator set (bitflip, byte-set, arith, boundary,
  dictionary, block delete/repeat, splice, havoc) and honour the `iterations`
  field, which was declared and never read.
  (done: `MutationEngine`. Same seed → identical crash fingerprints, so a
  finding is replayable.)
- [x] **One-click report from all sources** — merge SAST + SCA + fuzz + scan
      findings into a single exportable `.md`/`.json` (already partly wired).
  (done: "consolidated report" panel builds + downloads .md/.json from the
  session's captured scan/SAST/SCA/fuzz results)
- [x] **AI hookup in the UI** — surface provider reachability + model picker
      + a "verify" button so the AI section is obviously live vs. fallback.
  (done: model picker + AI full-loop + reachability badge in the Fix stage)

## Tier 2 — bring real tools in (what pros use)

- [x] **SCA demo fixture** — ship a small repo *with a committed lockfile* that
      reliably trips osv-scanner (e.g. pins an old log4j / requests) so the
      "dependencies are broken" demo never depends on network luck.
  (done: `demos/sca-demo/` pins lodash 4.17.20 → trips osv-scanner + trivy license)
- [x] **SBOM export** — expose the generated CycloneDX SBOM for download.
  (done: `GET /api/source/sca/sbom` + UI "download SBOM (.cdx.json)")
- [x] **Custom SAST rules library** — let the user save their Semgrep rule and
      re-run it over a whole tree (already validated per-file).
  (done: UI save/list/run-over-repo via `/rules/save` · `/rules/list` · `/rules/run`)
- [x] **License/secret scanning step** — trivy license + secret findings surfaced
      alongside CVEs (tool already installed).
  (done: `scan_licenses` + secrets surfaced in the SCA panel)
- [x] **Semgrep offline registry** — pre-bundle the rules so SAST works fully
      offline (avoids a network fetch on first scan).
  (done: 21 bundled rules; fixed `--offline` flag that made offline SAST return nothing)

## Tier 3 — the actual frontier (big wow, more work)

- [x] **AI full-loop** — fuzzer crash → AI root-cause → AI patch → re-fuzz to
      verify the fix removed it. One button.
  (done: `POST /api/source/ai/loop` + Fix-stage "AI full-loop" button)
- [x] **Local TLS interception lab** — mkcert + local CA so the fuzzer/SAST can
      target HTTPS web apps you own.
  (done: `tls_lab.py` — private CA + localhost cert + trust install + loopback HTTPS proxy via openssl/socat; endpoints under `/api/net/tls/*`)
- [x] **OSS-Fuzz-style auto-runner** — pull repo → build w/ sanitizers → fuzz N
      minutes → triaged report + patch diff (mirrors Google's public bug-hunting).
  (done: `POST /api/source/ossfuzz` + Fix-stage "OSS-Fuzz auto-run")
- [x] **SBOM → supply-chain map** — render dependency graph + reachability (which
      vulnerable call paths are actually hit).
  (done: `build_supply_chain_map` returns per-node `reachable` + `reachable_cves`;
  summary `reachable_nodes` + `vulnerable_reachable`; UI shows a reachable column.
  Reachability is dependency-graph (on an active path from the app root), labeled
  honestly as not a code-level call-graph claim.)

## Tier 4 — operator: engagements & lateral movement

- [x] **Persistent engagement store** — hosts/services/creds/vulns/attempts
      accumulate in SQLite across scans and restarts, instead of dying with the
      process like `JOBS`.
  (done: `engagement.py` + `/api/engagement/*`; scope CIDRs are enforced on
  every write, out-of-scope hosts are skipped *and reported*, DB is `0600`.)
- [x] **Credential propagation** — replay credentials already verified in the
      engagement against the rest of the in-scope estate, with a dry-run plan.
  (done: `propagate.py`; `…/propagate/plan` shows blast radius first.
  `cred_access` records where each cred works, so the graph emits a `pivot`
  edge only where a login actually succeeded. Attempt ledger means misses are
  never retried; `MAX_ATTEMPTS=500`.)

## Next up — the actual red-team gaps

- [x] **Attack paths to objectives** — let the operator declare crown jewels
      (a DC, a file server, `db-prod-01`) and compute *paths* to them, so a
      2.0 info-leak that pivots to the DC outranks a 9.8 on an isolated box.
      Needs the engagement graph above; this is the missing deliverable.
- [x] **ATT&CK technique IDs** — map every action/finding to a technique so the
      output speaks the defender's language. Cheap once paths exist.
- [x] **Detection guidance** — per technique, what telemetry a defender would
      have seen (log source, event ID). Worth more to a client than the vuln list.

## CTF / Live-target enhancements (added during 192.168.1.13 engagement)

- [x] **Container escape module** — detect dangerous caps/mounts and expose
      explicit escape helpers (ptrace attach, docker/containerd socket, cgroup
      release_agent). Detection is read-only; helpers are only called on demand.
      (done: `container_escape.py` + `POST /api/container_escape`)
- [x] **Lateral movement / network pivot** — route + interface mapping, SSH
      SOCKS and chisel tunnels, authenticated SMB session helper, and a
      SOCKS-aware TCP scan.
      (done: `lateral.py` + `POST /api/lateral`; tunnels/SMB are explicit calls)
- [x] **Database interrogation** — enumerate local APIs (ollama/zhc3/CAD worker)
      and extract flag-shaped secrets from SQLite/JSON/env/config files.
      (done: `db_interrogate.py` + `POST /api/db_interrogate`; bounded search
      roots instead of a blind `/` walk)
- [x] **CTF tool wrappers** — ZAP web scan, John hash cracking, aircrack-ng
      wireless, tshark pcap/live analysis, nmap NSE, each an explicit endpoint
      with a UI button.
      (done: `zap.py` `john.py` `aircrack.py` `tshark.py` + `/api/zap|john|aircrack|
      tshark/*|nmap/nse`)
- [x] **Fire TV toolkit** — ADB connect/pair/state/shell/keyevent/apps/pull/
      screenshot/logcat/install + recon (ports/banners/certs/eureka/auth-state)
      + mDNS/SSDP sweeps, each an explicit endpoint; mutating calls gated in
      sandbox.
      (done: `firetv.py` + `POST /api/firetv/*`; platform-tools `adb` in the
      image + capabilities inventory)
- [x] **Advanced fuzzing for container surfaces** — fuzz Docker API, containerd
      gRPC framing, kubelet, generic HTTP endpoints for RCE/DoS.
  (done: `container_fuzz.py` + `POST /api/container_surfaces|container_fuzz`;
  reuses the LabFuzzer engine/registry with TCP/TLS/unix/gRPC transports;
  read-only GET shapes by default, POST shapes only with `allow_mutating`;
  docker/grpc targets restricted to localhost; Exploit-tab card + e2e)
- [x] **Attack path graph to flag** — compute minimal path from foothold to flag
      (container escape → host → other containers → DB → flag). Show ATT&CK
      chain.
  (done: `flag_paths.py` + `GET /api/engagement/{id}/flag-paths` (fmt=json|md);
  one synthetic objective per flag host, flags attached to the final hop,
  ATT&CK techniques on every path; Score-tab "Flag paths" button)

## Infra / shipping

- [x] **LLM provider choice removed from containers** — the compose ollama
      sidecar is gone; the AI provider is pure env-config (`H4K_AI_PROVIDER`,
      `H4K_AI_URL/KEY/MODEL`), with a keyless host-side relay for opencode
      free models at `h4k/scripts/opencode_relay.py`.
- [x] **CI**: GitHub Actions running lint + tests on push (reproducible quality
      gate for the class).
  (done: `.github/workflows/ci.yml` runs `make lint` + `make coverage` on push/PR)
- [x] **Release packaging** — tagged image + one-line `docker run` for classmates.
  (done: `scripts/release.sh <ver>` builds/tags/pushes and prints the one-liner)
- [x] **Selenium end-to-end suite** — a real browser drives the real console
      against a real API, so UI regressions cannot ship silently.
  (done: `tests/e2e/` + `make e2e` + a CI job. 27 tests: boot, navigation,
  scope picker, report preview, crown jewels, attack paths, ATT&CK panel and a
  full autopilot walk. The `page` fixture fails a test on any uncaught
  JavaScript error — that is how the missing `renderReportPreview()` was found.)
- [x] **Sandbox mode** — deterministic, offline stand-ins for nmap/hydra/
      Metasploit so demos, CI and the browser suite never touch a network.
  (done: `services/sandbox.py` + `H4K_SANDBOX=1` + `POST /api/engagement/sandbox-seed`)
- [x] **Capability report** — `GET /api/capabilities` reports installed tools,
      Metasploit reachability *and database state*, storage and wordlists, and
      warns about anything that would fail silently. The console shows it as a
      footer badge; `scripts/sanity_check.py` asserts on it.
  (done: `services/capabilities.py` + `/api/capabilities` + UI badge. It
  catches the classic "Metasploit is up but its database is not" case, where
  every scan comes back empty.)
- [x] **Banner-aware CVE matching** — version ranges are keyed by the product
      actually detected on the wire, so a patched vsftpd 3.0.3 is no longer
      flagged with the 2.3.4 backdoor CVE.
- [x] **Engagement snapshots + path export** — export/import an engagement as
      a portable, scope-checked snapshot; export attack paths as markdown.
- [x] **Passive auto-scan on boot** — as soon as the API comes up it begins
      building a network and service map of the local subnet (recon only: no
      credential testing, no exploitation), folds the result into a default
      engagement, and re-scans on a cadence. The map is live at `/api/map`
      and in the console (`auto-scan: running · N hosts · M services`).
  (done: `services/auto_scan.py`, `GET/POST /api/map*`, UI status badge.
  Configurable via `H4K_AUTO_SCAN`, `H4K_AUTO_SCAN_CIDR`,
  `H4K_AUTO_SCAN_INTERVAL`, `H4K_AUTO_SCAN_DEPTH`.)
- [x] **Documentation set** — user, developer and security documentation that
      lives in the repo and is reviewed with the code.
  (done: `docs/` — quickstart, concepts, workflows, UI guide, safety,
  troubleshooting, architecture, API reference, service reference, data model,
  testing guide, contributing, release process, threat model, scope spec,
  secrets handling, examples.)

## Evaluated & rejected

- **ExploitGym** (`sunblaze-ucb/exploitgym`) — not adopted. It's a CyberGym-style
  Docker-in-Docker eval rig whose only agent backends (Codex / Claude Code /
  Gemini CLI) all require a cloud LLM API key; there is no local/no-key path,
  and it needs Python 3.12+ and per-task target images + a squid firewall +
  controller. It also clashes with the project's local-first, no-weaponization
  stance. The exploit-first AI loop (minimal trigger → patch → verify) already
  demonstrates the same "AI turns a finding into a confirmed attack" idea
  locally via the keyless opencode relay.

---

## Suggested order for a 10-minute class demo

1. **Crash → minimize → patch** (Tier 1): fuzz vulnlab → ASan hit → minimized
   repro → patch candidate → re-fuzz clean.
2. **Custom Semgrep rule** (Tier 2) matching a pattern you invent live.
3. **SCA on the fixture repo** (Tier 2) → instant CVE hits from the lockfile.
4. **AI root-cause + patch** via the local opencode relay (Tier 1/3), noting the ethics gate.

**h4k**, out.

## Backlog — 100 candidate features (prioritized 1–100, risk → wow → debt)

Ordered for **WOW factor, reliability, quality, security, and testing
payoff**: checkable security work first, then testing/reliability
force-multipliers and demo wow, with tech-debt paydown threaded through.
Each open item carries its primary driver — [risk], [wow] or [debt]. Items 1–25 are done and merged. Items marked *(in flight:
PR #N)* have an open PR implementing exactly that scope — work the
lowest-numbered item that is neither done nor in flight, and never duplicate
in-flight work. Deliberately cut as out of scope: mobile triage, themes,
i18n, QR share, wardrive/SDR/RFID/USB hardware, the air-gapped model bundle,
#189 rate-limit map (covered by Done #20), #190 batching check (covered by
Done #17). All opt-in where aggressive (D5/D24); sandbox stand-ins required
where network/tooling is involved.

1. **Interactive attack-graph canvas** [wow] — clickable pan/zoom nodes, PNG export.
  (done: `services/graph_canvas.py` + `GET /api/engagement/{id}/graph/canvas` returns deterministic x/y + legend; Score-tab SVG with drag-pan, wheel-zoom, click details, PNG export; unit + e2e `test_graph_canvas`.)
2. **Nuclei template runner** [risk] — opt-in CVE templates, offline bundle + ledger.
  (done: `h4k/data/nuclei-templates/` ships 3 CVE templates; `POST /api/nuclei` gains `offline` + `engagement_id` ledger ingest with scope enforcement; `GET /api/nuclei/templates` exposes the bundle; sandbox canned finding; Recon card + palette button; unit + e2e `test_nuclei_*`.)
3. **Credential hygiene report** [risk] — reuse/weak/default summary per engagement.
  (done: `services/hygiene.py` + `GET /api/engagement/{id}/hygiene` (reuse/weak/default + 0-100 score, read-only); Pivot ledger card button + findings; unit + e2e `test_hygiene*`.)
4. **NSE vuln suggest-and-run** [risk] — service → script map, explicit run only.
  (done: `services/nse_suggest.py` curated map (16 services + generic fallback) + `GET /api/nse/suggest|services`; run stays explicit `POST /api/nmap/nse`; Recon NSE card suggest → Run flow; unit + e2e `test_nse*`.)
5. **Kerberos roast helpers** [risk] — AS-REP/kerberoast → John, explicit only.
  (done: `services/kerberos.py` impacket GetNPUsers/GetUserSPNs + hash extract + optional `JohnRunner` crack; `POST /api/kerberos/asrep|kerberoast` (sandbox canned hashes, crack skipped); Pivot roast card + palette; unit + e2e `test_krb*`/`test_kerberos`.)
6. **Lockout-aware spray** [risk] — jitter, per-user cap, ledger stop.
  (done: `services/spray_guard.py` + `PropagationService` policy (per-user cap, jitter, `locked` ledger state, locked users never retried); plan/run surface policy + held stats; Pivot ledger inputs; unit + e2e `test_spray*`.)
7. **Loot vault with redaction** [risk] — creds/keys/flags, masked export.
  (done: `services/loot_vault.py` masked rollup + md/json export, reveal-gated; `GET /api/engagement/{id}/vault|vault/export`; Score vault card masked-first + reveal checkbox + MD export; unit + e2e `test_loot_vault`/`test_vault_ui`.)
8. **PDF client report** [wow] — one-click assessment PDF.
  (done: `services/pdf_report.py` reportlab render + `GET /api/session/report?fmt=pdf` attachment (passwords masked); Report card Download PDF; `reportlab` in requirements + image; unit + e2e `test_pdf*`.)
9. **JARM/JA3 TLS fingerprints** [risk] — C2/malware leads from handshakes.
  (done: `services/tls_fingerprint.py` stdlib handshake inventory + stable fingerprint + operator watchlist (exact match) + heuristic leads; `POST /api/tls/fingerprint` sandbox canned; Recon TLS card + palette; unit + e2e `test_tls*`. Honest scope: not raw-ClientHello JARM — stdlib cannot emit the probes, exact-match only.)
10. **IPv6 discovery** [risk] — NDP/arp6 + nmap -6, scope-checked.
  (done: `services/ipv6_discovery.py` NDP parse + explicit-CIDR nmap -6 only (never a blind v6 sweep) + scope-enforced asset ledger; `POST /api/net/ipv6/discover` sandbox canned; Discover Neighbors-v6 button + palette; unit + e2e `test_ipv6*`.)
11. **TLS cert inventory** [risk] — expiry/weak-cipher/self-signed leads.
  (done: `services/cert_inventory.py` multi-host inventory + 30-day expiry/self-signed/weak leads + scope-enforced vuln ledger; `POST /api/tls/inventory` sandbox canned; TLS card inventory row; unit + e2e `test_cert*`.)
12. **KEV/EPSS enrichment** [risk] — CISA KEV flag + EPSS score on vulns.
  (done: `services/kev.py` + `h4k/data/kev.json` (37 real KEV+EPSS entries, sources+date stamped) + check/enrich/refresh endpoints; Recon KEV card with opt-in refresh; unit (incl. keep-table-on-failure) + e2e `test_kev*`.)
13. **False-positive tuner** [risk] — suppress with reason + expiry.
  (done: `vuln_suppressions` table (migration-safe) + suppress/unsuppress/list/effective endpoints (out-of-scope refused, expired rows inert); Recon Suppress-finding card + list; unit + e2e `test_suppress*`.)
14. **Privesc suggester** [risk] — lin/winPEAS-style checklist, read-only.
  (done: `services/privesc_suggest.py` 10 checks (SUID/GTFOBins, caps, sudo, PATH, cron, NFS, groups, shadow, modules) with fix hints, passwordless + writeless; `POST /api/privesc/suggest` sandbox canned; Pivot Checklist button; unit + e2e `test_privesc_suggest*`.)
15. **Kubelet unauth audit** [risk] — read-only checks.
  (done: `services/kubelet_audit.py` stdlib HTTPS GET checklist (/healthz, anonymous /pods, /metrics, 10255 read-only-port probe, no exec/writes) + scope-enforced vuln ledger; `POST /api/kubelet/audit` sandbox canned; Container card Audit-kubelet row + palette; unit (incl. canned-transport logic + unreachable) + e2e `test_kubelet_audit*`.)
16. **K8s RBAC audit** [risk] — over-permissive roles flagged.
  (done: `services/rbac_audit.py` offline `safe_load_all` manifest audit (* verbs/resources, escalate/bind/impersonate, secret read, pod create, authenticated/unauthenticated + cluster-admin bindings) + scope-enforced vuln ledger; `POST /api/rbac/audit` (400 empty docs) sandbox canned; Container card Audit-RBAC row + palette; unit + e2e `test_rbac_audit*`.)
17. **Cloud metadata SSRF pack** [risk] — 169.254 probes, opt-in.
  (done: `services/ssrf_pack.py` 10-payload pack (AWS/GCP/Azure + decimal/octal/hex bypasses) with baseline + marker-differential verdicts, urllib-only; `POST /api/ssrf/probe` (400 bad target, 404 unknown engagement) sandbox canned; Web card SSRF row + palette; unit (incl. live safe/vulnerable stub servers) + e2e `test_ssrf_pack*`.)
18. **JWT tester** [risk] — crack + alg-confusion, lab-only.
  (done: `services/jwt_tester.py` offline audit (unsigned/long-lived/no-exp/kid/jku flags) + capped stdlib HMAC crack (built-in + pasted wordlist, masked reporting) + live none/empty-sig/confusion-key mutants vs marker; `POST /api/jwt/test` (400 bad token/url, 404 unknown engagement) sandbox canned; Web card JWT row + palette; unit (incl. strict vs open stub servers) + e2e `test_jwt_tester*`.)
19. **Sanitizer diff** [risk] — ASan vs UBSan vs MSan compare.
  (done: `services/sanitizer_diff.py` offline pasted-report classify (incl. MSan uninit flagship) + per-family would-detect matrix from a stated coverage table + blind spots + one confirming rebuild (flags/env/replay); `POST /api/source/sanitizer/diff` (400 empty) sandbox canned; Fuzz-lab row + palette; unit + e2e `test_sanitizer_diff*`.)
20. **Rate-limit-aware fuzz** [risk] — 429 backoff + jitter.
  (done: `services/ratefuzz.py` bounded polite probe (Retry-After seconds/date honored + capped, exponential base with decay, ±jitter, per-request timeline; injectable sleeper) + no-throttle MEDIUM finding (CWE-799) vs honored-throttle INFO; `POST /api/rate_fuzz` (400 bad url, 404 unknown engagement) sandbox canned; Fuzz-lab row + palette; unit (incl. open vs throttling stub servers, no-sleep) + e2e `test_ratefuzz*`.)
21. **Fuzz sharding** [wow] — N workers, merged registry.
  (done: `services/fuzz_shard.py` coordinator (deterministic disjoint slices, seeded per worker, shared locked `CrashRegistry`, per-worker errors never fatal, stable sorted output) + `POST /api/fuzz/shard` (400 no target) sandbox canned; Fuzz-lab row + palette; unit (incl. live RST stub proving cross-worker dedup to 1) + e2e `test_fuzz_shard*`.)
22. **SARIF import/export** [debt] — Semgrep interchange.
  (done: `services/sarif_exchange.py` h4k→SARIF 2.1.0 (level map, CWE tags, deduped rules, lossless h4k_severity round-trip) + SARIF→h4k (rule metadata, CWE tags, origin noted, per-result errors); `POST /api/source/sarif/export|import` (400 bad/empty) sandbox canned; Score card + palette + SARIF file download; unit (incl. real Semgrep-shaped fixture) + e2e `test_sarif_exchange*`.)
23. **Taint rules pack** [risk] — source→sink Python/JS/PHP.
  (done: `services/taint_pack.py` 15-rule data-driven pack (py/js/php sources, sinks, sanitizers) + 6-line windowed source→sink match with sanitizer clearing + one-hit-per-rule-per-file; `POST /api/source/taint/scan` (=== path === bundle or files, 400 empty, 404 unknown engagement) sandbox canned; Container card row + palette; unit (incl. window edge + sanitizer clearing) + e2e `test_taint_pack*`.)
24. **Secret baseline + allowlist** [risk] — noise reduction.
  (done: `services/secret_baseline.py` bundle secret scan (7 shapes) + fingerprint baseline diff + audited allowlist suppression + new-only scope-enforced ledger; `POST /api/source/secrets/scan` (=== path === bundle or files, 400 empty/bad-allowlist, 404 unknown engagement) sandbox canned; Container card row + palette; unit + e2e `test_secret_baseline*`.)
25. **Reachability filter** [risk] — import-graph prunes dead code.
  (done: `services/reachability.py` module graph (py ast + JS/PHP imports, same-dir relative resolution, explicit-or-guessed entries flagged) + reached/unreached split + unresolved list; `POST /api/source/reachability` (400 empty) sandbox canned; Container card row + palette; unit + e2e `test_reachability*`; merged via #85.)
26. **DAST spider + auth crawl** [risk] — depth-bounded, scope-checked link/form map. *(was #3)*
  (done: `services/dast_spider.py` same-origin BFS + auth header/cookie + `POST /spider` with scope-enforced asset ledger; sandbox canned map; DAST spider card + palette cmd; unit + e2e `test_*spider*`.)
27. **Scheduled re-scans + diff alerts** [risk] — cadence per engagement, MD digest. *(was #5; in flight: PR #26)*
28. **SMB share enumerator** [risk] — shares/ACLs, read-only, into asset graph. *(was #7; in flight: PR #28)*
29. **LLMNR/NBT-NS poison lab** [risk] — container-only listener + capture. *(was #9; in flight: PR #30)*
30. **Session post-exploit recon pack** [risk] — sysinfo/getuid/loot timeline. *(was #11; in flight: PR #32)*
31. **Engagement timeline view** [risk] — scan→creds→sessions→paths chronology. *(was #13; in flight: PR #34)*
32. **Engagement compare/diff** [risk] — vulns/paths across runs. *(was #15; in flight: PR #36)*
33. **SNMP community sweep** [risk] — community + MIB walk, opt-in. *(was #17; in flight: PR #38)*
34. **mDNS/SSDP persistent map** [risk] — sweeps persist as assets. *(was #19; in flight: PR #40)*
35. **Shodan/Censys BYO import** [risk] — JSON → leads, no key in repo. *(was #21; in flight: PR #42)*
36. **CPE auto-correlate** [risk] — banner → CPE → CVE matcher. *(was #22; in flight: PR #43)*
37. **CVSS v4 re-score** [risk] — override with audit trail. *(was #24; in flight: PR #45)*
38. **BloodHound ingest** [wow] — SharpHound JSON → graph overlay. *(was #26; in flight: PR #47)*
39. **XSS catch lab** [risk] — token/cookie catch + replay, lab-only. *(was #28; in flight: PR #49)*
40. **SQLmap tamper flow** [risk] — dump → ledger, explicit only. *(was #29; in flight: PR #50)*
41. **Hydra tune + resume** [risk] — parallel profile, checkpoint resume. *(was #30; in flight: PR #51)*
42. **ffuf/wpscan pack** [risk] — dir + plugin enum, explicit. *(was #31; in flight: PR #52)*
43. **Impacket one-clicks** [risk] — secretsdump/GetNPUsers, explicit creds. *(was #32; in flight: PR #53)*
44. **NTLM relay lab** [risk] — container-only, explicit. *(was #33; in flight: PR #54)*
45. **Chisel/sshuttle pivot + SOCKS-aware scan** [risk] — one-click tunnel + proxied rescan. *(was #34, #35; in flight: PR #55)*
46. **Container image scan** [risk] — trivy image → engagement vulns. *(was #36; in flight: PR #57)*
47. **Docker socket guard** [risk] — detect + policy suggestion. *(was #38; in flight: PR #59)*
48. **Helm chart SAST** [risk] — templating + secret checks. *(was #40; in flight: PR #61)*
49. **Terraform/IaC scan** [risk] — Checkov-style offline misconfigs. *(was #41; in flight: PR #62)*
50. **IAM key hygiene** [risk] — age/rotation, read-only. *(was #43; in flight: PR #64)*
51. **S3 policy linter** [risk] — public/ACL offline eval. *(was #44; in flight: PR #65)*
52. **WebSocket fuzz** [risk] — frame mutation + replay. *(was #45; in flight: PR #66)*
53. **gRPC enumerator + fuzz** [risk] — reflection + payload shapes. *(was #46; in flight: PR #67)*
54. **GraphQL introspection + fuzz** [risk] — field/depth probes. *(was #47; in flight: PR #68)*
55. **OpenAPI import → fuzz** [risk] — spec-driven targets. *(was #48; in flight: PR #69)*
56. **Header/cookie session fuzz** [risk] — auth-bypass leads. *(was #49; in flight: PR #70)*
57. **Corpus sync** [debt] — shared corpus dir across runs. *(was #51; in flight: PR #72)*
58. **AFL++ persistent runner** [wow] — harness + stats. *(was #52; in flight: PR #73)*
59. **Crash bisection** [wow] — input halve to minimal trigger. *(was #54; in flight: PR #75)*
60. **PCAP → seed replay** [wow] — deterministic fuzz seeds. *(was #55; in flight: PR #76)*
61. **Stateful fuzz + auth profiles** [risk] — login → authed-flow fuzz. *(was #56, #58; in flight: PR #77)*
62. **Coverage HTML import** [wow] — llvm-cov badge in UI. *(was #60; in flight: PR #81)*
63. **SAST CI gate + delta + inline suppress** [risk] — fail PRs on new high-severity findings; diff-only results; NOSAST with expiry + owner. *(merges old #65, #66, #67; old #65 done via #87, old #66 done via #88, old #67 done via #89)*
  (done: threshold CI gate + SAST diff + NOSAST waivers with expiry/owner; `POST /api/source/ci/gate|sast/delta|suppress/match` sandbox canned; Container card rows + palette; unit + e2e `test_ci_gate*`, `test_sast_delta*`, `test_suppress*`.)
64. **Verify-fix retest + flaky detector + coverage-green + dedup** [risk] — one-click finding rescan; appears/disappears flagging; verified/lead/suppressed stats; one finding per vuln; keep the 90% coverage gate green and quarantine flaky e2e (quarantine list + retries, never silent skips). *(merges old #128, #129, #130, #177)*
  (done: `services/verify_fix.py` baseline-vs-rescan (+ history) retest with exact-match persists/fixed/new + reappeared-flaky flag + dedup + suppressed tally; `POST /api/source/verify/fix` (400 bad entries) sandbox canned; `tests/e2e/quarantine.txt` + conftest auto-skip with reason; Container card row + palette; unit + e2e `test_verify_fix*`.)
65. **Command palette** [wow] — Ctrl-K ops launcher for every card action. *(merges old #95)*
  (done: palette `runCmd` dispatches generically via `data-tab` + `data-btn` (clicks the real card handler — same guards, no parallel path); all 89 card buttons audited — every run action has an entry, non-launchable toggles/resets/deletes/demo-seeders/form-openers excluded and documented; filter matches label and command id; unit `test_palette.py` enforces the contract going forward + e2e `test_palette_ui*`.)
66. **Multi-lang SAST: Go + Rust** [risk] — core source→sink rules for Go and Rust services. *(merges old #68)*
  (done: `services/multilang_sast.py` 10-rule pack (6 Go: exec/sql/template.HTML/traversal/SSRF/gob-yaml; 4 Rust: Command/sqlx/fs/reqwest) with 6-line windowed matching + sanitizer clearing + one-hit-per-rule-per-file; `POST /api/source/sast/multilang` (=== path === bundle or files, 400 empty/bad, 404 unknown engagement) sandbox canned; Container card row + palette; unit (incl. window edge + sanitizer clearing) + e2e `test_multilang*`.)
67. **Vuln-lib taint + VEX statements** [risk] — vulnerable-dependency → sink paths; not-affected with justification. *(merges old #69, #70)*
68. **Typosquat heuristics + SLSA provenance ingest** [risk] — malicious-package signals; build-info provenance records. *(merges old #71, #72)*
69. **Supply-chain policy: license gate + SBOM diff + pin bot** [risk] — deny/warn license rules; new deps/CVEs per commit; suggested pinned upgrades. *(merges old #73, #74, #75)*
70. **OS package audit + base-image freshness** [risk] — dpkg/rpm/apk → CVE matching; image age/EOL + slim suggestions. *(merges old #76, #77)*
71. **Rotation planner + patch-diff verifier + PoC capture** [wow] — rotate steps for found secrets; before/after re-fuzz proof; headless exploit-flow recording. *(merges old #78, #79, #80)*
72. **Disclosure tracker + CVSS builder + CWE browser** [risk] — 90-day disclosure timeline with reminders; pick-a-score vector builder; offline CWE dictionary + suggest. *(merges old #81, #82, #83)*
73. **Vuln intel: Exploit-DB + MSF delta + tech→CVE** [risk] — offline Exploit-DB mirror search; new modules since update; WhatWeb/Wappalyzer tech → CVE auto-link. *(merges old #84, #85, #178, #179)*
74. **AI patch-rank + test-gen + false-positive judge** [wow] — 3 patch candidates with tradeoffs; regression-test skeletons; why-not-exploitable explanations. *(merges old #86, #87, #88)*
75. **AI NL query + similar-bug search** [wow] — read-only natural-language graph questions; embedding search for twin findings. *(merges old #89, #94)*
76. **Prompt guard + AI cost badge + eval harness** [debt] — strip secrets before LLM send; tokens/sec + fallback reason; accuracy on fixtures. *(merges old #90, #91, #93)*
77. **Purple-team pack: D3FEND map + tabletop + deception + replay** [wow] — countermeasure per technique; scenario generator; honeypot/canary suggest; attack → detection check. *(merges old #96, #97, #98, #99)*
78. **SIEM/SOAR handoff pack** [risk] — CEF/LEEF syslog export; STIX bundle; MISP push; TheHive case; finding → ticket/webhook dispatch (all opt-in). *(merges old #100, #101, #102, #103, #104, #105)*
79. **GRC tracking: SLA + risk accept + compliance crosswalk** [risk] — ageing + burndown; accept-with-expiry + signer; CIS/NIST/PCI map. *(merges old #106, #107, #108)*
80. **Exec dashboard + portfolio + role views** [wow] — risk trend + exposure score; multi-engagement rollup; operator/viewer/auditor. *(merges old #109, #110, #111)*
81. **Audit log + backup/restore + retention/GC** [debt] — immutable op log + export; encrypted bundles; prune pcaps/corpora per engagement; fuzz-artifact quotas. *(merges old #112, #113, #131, #132)*
82. **Evidence locker + custody + offline field kit** [risk] — pcap/loot with hash chain; hash + signer export; air-gap import bundle. *(merges old #114, #115, #116)*
83. **Keyboard-first + screen-reader pass** [debt] — shortcuts + focus traps; ARIA live regions. *(merges old #121, #122)*
84. **Finding workflow: bulk ops + tags + comments + assign + kanban** [debt] — tag/suppress N findings; saved filters; per-finding threads; owner + due dates; todo/doing/done. *(merges old #123, #124, #125, #126, #127)*
85. **API keys + per-route rate limit + OIDC login** [debt] — scoped tokens; token-bucket throttle; lab SSO. *(merges old #133, #134, #135)*
86. **Sandbox profiles + resource caps + fair-share + remote workers** [debt] — seccomp/apparmor per job; CPU/mem/timeout caps; priority + preempt queue; nmap/fuzz agents. *(merges old #136, #137, #138, #139)*
87. **Lab traffic kit: Wireguard testbed + shaper + sinkhole + scrubber** [wow] — mesh VPN spin-up; slow/lossy target sim; malicious-domain sinkhole; strip payloads, keep flows. *(merges old #140, #141, #142, #143)*
88. **Telemetry ingest: NetFlow + Zeek + Suricata + Sigma** [risk] — flow → assets; Zeek logs → assets; EVE alerts as leads; Sigma-hit → finding import. *(merges old #144, #145, #146, #147)*
89. **Binary triage: YARA + ClamAV + Ghidra list + capa + firmware unpack** [risk] — runner over loot/samples; AV metadata; functions/imports; capability tags; binwalk → SBOM + secrets. *(merges old #148, #149, #150, #151, #152)*
90. **IoT/OT pack: creds + modbus + BACnet/MQTT + CoAP + SIP** [risk] — printer/cam default creds; read-only modbus/s7; passive subscribe; scope-checked probes; opt-in SIP enum. *(merges old #157, #158, #159, #160, #161)*
91. **AD credential attacks: kerbrute + spray charter + hash timeline + PtH** [risk] — opt-in user enum; lockout-aware spray policy; crack → propagate suggest; lab-only pass-the-hash. *(merges old #162, #166, #167, #170)*
92. **BloodHound CE wrapper + path overlay** [wow] — collector run packaging; shortest-path overlay on the graph. *(merges old #163, #165)*
93. **AD domain audit: ADCS + ticket-forge + DCSync + LAPS + GPO** [risk] — ESC1-8 read-only checks; forgery signal detectors; replication-rights audit; rotation + exposure; offline GPO lint. *(merges old #164, #168, #169, #171, #172)*
94. **Endpoint telemetry: Sysmon deploy + Velociraptor + osquery + Wazuh** [risk] — lab-only Sysmon config; collector artifacts; fleet inventory import; agent status. *(merges old #173, #174, #175, #176)*
95. **Web headers + cookies + CORS audit** [risk] — Lighthouse-style security headers; Secure/HttpOnly/SameSite flags; origin-reflection checks, lab-only. *(merges old #180, #181, #182)*
96. **Web inject pack: SSTI + XXE + deser index + SSRF→RCE + allowlist tester** [risk] — Jinja/Twig probes; oob-safe XXE; gadget index (hints, no payloads); metadata + internal SSRF tester. *(merges old #184, #185, #186, #187, #183)*
97. **Web logic: IDOR/race/price templates + takeover + hijack + JS harvester** [risk] — broken-object/race/price checklists; CNAME → unclaimed; broken-link targets; secrets + sourcemaps. *(merges old #188, #193, #194, #195)*
98. **Cache deception + host-header poisoning** [risk] — path-confusion cache checks; host-header injection, lab-only. *(merges old #191, #192)*
99. **Fuzz workbench: dictionary + encoder + regex tester** [debt] — custom fuzz payload sets; b64/url/hex/jwt client-side encoder; live-highlight rule tester. *(merges old #196, #197, #198)*
100. **Nightly autopilot + demo seeder** [wow] — cron + webhook recon digest; one-click 5-minute talk seed. *(merges old #199, #200)*
