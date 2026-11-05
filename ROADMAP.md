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

## Backlog — 200 candidate features (prioritized 1–200)

Ordered by **demo wow × real value ÷ effort**. P1–30 next, 31–100 high-value,
101–160 depth, 161–200 stretch/research. All opt-in where aggressive (D5/D24);
sandbox stand-ins required where network/tooling is involved.

1. **Interactive attack-graph canvas** — clickable pan/zoom nodes, PNG export.
  (done: `services/graph_canvas.py` + `GET /api/engagement/{id}/graph/canvas` returns deterministic x/y + legend; Score-tab SVG with drag-pan, wheel-zoom, click details, PNG export; unit + e2e `test_graph_canvas`.)
2. **Nuclei template runner** — opt-in CVE templates, offline bundle + ledger.
  (done: `h4k/data/nuclei-templates/` ships 3 CVE templates; `POST /api/nuclei` gains `offline` + `engagement_id` ledger ingest with scope enforcement; `GET /api/nuclei/templates` exposes the bundle; sandbox canned finding; Recon card + palette button; unit + e2e `test_nuclei_*`.)
3. **DAST spider + auth crawl** — depth-bounded, scope-checked link/form map.
4. **Credential hygiene report** — reuse/weak/default summary per engagement.
  (done: `services/hygiene.py` + `GET /api/engagement/{id}/hygiene` (reuse/weak/default + 0-100 score, read-only); Pivot ledger card button + findings; unit + e2e `test_hygiene*`.)
5. **Scheduled re-scans + diff alerts** — cadence per engagement, MD digest.
6. **NSE vuln suggest-and-run** — service → script map, explicit run only.
7. **SMB share enumerator** — shares/ACLs, read-only, into asset graph.
  (done: `services/smb_shares.py` smbclient/smbmap parse + `POST /api/smb/shares` (null session default) with scope-enforced share ledger (`shares` table, `GET .../shares`, included in graph payload); Recon SMB card + palette; unit + e2e `test_smb*`.)
8. **Kerberos roast helpers** — AS-REP/kerberoast → John, explicit only.
9. **LLMNR/NBT-NS poison lab** — container-only listener + capture.
10. **Lockout-aware spray** — jitter, per-user cap, ledger stop.
11. **Session post-exploit recon pack** — sysinfo/getuid/loot timeline.
12. **Loot vault with redaction** — creds/keys/flags, masked export.
13. **Engagement timeline view** — scan→creds→sessions→paths chronology.
14. **PDF client report** — one-click assessment PDF.
15. **Engagement compare/diff** — vulns/paths across runs.
16. **JARM/JA3 TLS fingerprints** — C2/malware leads from handshakes.
17. **SNMP community sweep** — community + MIB walk, opt-in.
18. **IPv6 discovery** — NDP/arp6 + nmap -6, scope-checked.
19. **mDNS/SSDP persistent map** — sweeps persist as assets.
20. **TLS cert inventory** — expiry/weak-cipher/self-signed leads.
21. **Shodan/Censys BYO import** — JSON → leads, no key in repo.
22. **CPE auto-correlate** — banner → CPE → CVE matcher.
23. **KEV/EPSS enrichment** — CISA KEV flag + EPSS score on vulns.
24. **CVSS v4 re-score** — override with audit trail.
25. **False-positive tuner** — suppress with reason + expiry.
26. **BloodHound ingest** — SharpHound JSON → graph overlay.
27. **Privesc suggester** — lin/winPEAS-style checklist, read-only.
28. **XSS catch lab** — token/cookie catch + replay, lab-only.
29. **SQLmap tamper flow** — dump → ledger, explicit only.
30. **Hydra tune + resume** — parallel profile, checkpoint resume.
31. **ffuf/wpscan pack** — dir + plugin enum, explicit.
32. **Impacket one-clicks** — secretsdump/GetNPUsers, explicit creds.
33. **NTLM relay lab** — container-only, explicit.
34. **Chisel/sshuttle pivot** — one-click tunnel + proxied rescan.
35. **SOCKS-aware scan** — TCP scan via pivot.
36. **Container image scan** — trivy image → engagement vulns.
37. **Kubelet unauth audit** — read-only checks.
38. **Docker socket guard** — detect + policy suggestion.
39. **K8s RBAC audit** — over-permissive roles flagged.
40. **Helm chart SAST** — templating + secret checks.
41. **Terraform/IaC scan** — Checkov-style offline misconfigs.
42. **Cloud metadata SSRF pack** — 169.254 probes, opt-in.
43. **IAM key hygiene** — age/rotation, read-only.
44. **S3 policy linter** — public/ACL offline eval.
45. **WebSocket fuzz** — frame mutation + replay.
46. **gRPC enumerator + fuzz** — reflection + payload shapes.
47. **GraphQL introspection + fuzz** — field/depth probes.
48. **OpenAPI import → fuzz** — spec-driven targets.
49. **Header/cookie session fuzz** — auth-bypass leads.
50. **JWT tester** — crack + alg-confusion, lab-only.
51. **Corpus sync** — shared corpus dir across runs.
52. **AFL++ persistent runner** — harness + stats.
53. **Sanitizer diff** — ASan vs UBSan vs MSan compare.
54. **Crash bisection** — input halve to minimal trigger.
55. **PCAP → seed replay** — deterministic fuzz seeds.
56. **Stateful fuzz** — login → authed-flow fuzz.
57. **Rate-limit-aware fuzz** — 429 backoff + jitter.
58. **Authenticated fuzz profiles** — cookie/header presets.
59. **Fuzz sharding** — N workers, merged registry.
60. **Coverage HTML import** — llvm-cov badge in UI.
61. **SARIF import/export** — Semgrep interchange.
62. **Taint rules pack** — source→sink Python/JS/PHP.
63. **Secret baseline + allowlist** — noise reduction.
64. **Reachability filter** — import-graph prunes dead code.
65. **Rule CI gate** — fail on high-severity SAST.
66. **Delta SAST** — diff-only findings per PR.
67. **Inline suppress** — NOSAST with expiry + owner.
68. **Multi-lang pack** — Go/Rust/Ruby/PHP/C# rules.
69. **Vuln-lib taint** — vuln dep → sink path.
70. **VEX statements** — not-affected with justification.
71. **Typosquat heuristics** — malicious-package signals.
72. **Provenance ingest** — SLSA/build-info.
73. **License policy gate** — deny/warn rules.
74. **SBOM diff** — new deps/CVEs per commit.
75. **Pin bot** — suggest pinned upgrades.
76. **OS package audit** — dpkg/rpm/apk → CVE.
77. **Base-image freshness** — age/EOL + slim suggest.
78. **Rotation planner** — found secret → rotate steps.
79. **Patch diff verifier** — before/after re-fuzz proof.
80. **PoC capture** — headless exploit-flow recording.
81. **Disclosure tracker** — 90-day timeline + reminders.
82. **CVSS vector builder** — pick metrics → score.
83. **CWE browser** — offline dictionary + suggest.
84. **Exploit-DB mirror search** — offline index.
85. **MSF module delta** — new modules since update.
86. **AI patch-rank** — 3 candidates + tradeoffs.
87. **AI test-gen** — regression-test skeleton for patch.
88. **AI false-positive judge** — why-not-exploitable explainer.
89. **AI NL query** — read-only graph questions.
90. **AI cost badge** — tokens/sec + fallback reason.
91. **Prompt guard** — strip secrets before LLM send.
92. **Air-gapped model bundle** — quantized import.
93. **Model eval harness** — accuracy on fixtures.
94. **Similar-bug search** — embed + nearest findings.
95. **Command palette** — Ctrl-K ops.
96. **D3FEND map** — countermeasure per technique.
97. **Deception planner** — honeypot/canary suggest.
98. **Purple replay** — attack → detection check.
99. **Tabletop generator** — scenario MD from engagement.
100. **CEF/LEEF export** — syslog SIEM handoff.
101. **STIX bundle export** — portable threat intel.
102. **MISP push** — opt-in event create.
103. **TheHive case** — opt-in case create.
104. **Ticket sync** — finding → Jira/Linear issue.
105. **Webhook dispatcher** — finding/lead → URL.
106. **SLA tracker** — ageing + burndown.
107. **Risk accept flow** — accept with expiry + signer.
108. **Compliance crosswalk** — CIS/NIST/PCI map.
109. **Exec dashboard** — risk trend + exposure score.
110. **Portfolio view** — multi-engagement rollup.
111. **Role views** — operator/viewer/auditor.
112. **Audit log** — immutable op log + export.
113. **Backup/restore** — encrypted bundle.
114. **Evidence locker** — pcap/logs with hash chain.
115. **Custody export** — hash + signer.
116. **Offline field kit** — export → air-gapped import.
117. **QR share** — link + scope fingerprint.
118. **Mobile triage** — small-screen finding triage.
119. **Themes** — dark/light/high-contrast.
120. **i18n skeleton** — en + second lang.
121. **Keyboard-first** — shortcuts + focus traps.
122. **Screen-reader pass** — ARIA + live regions.
123. **Bulk actions** — tag/suppress/assign N findings.
124. **Tags + saved filters** — my-RCE, my-XSS.
125. **Finding comments** — per-finding threads.
126. **Assign + due dates** — owner + SLA.
127. **Kanban fix board** — todo/doing/done.
128. **Verify-fix retest** — one-click finding rescan.
129. **Flaky detector** — appears/disappears flag.
130. **Confidence stats** — verified/lead/suppressed.
131. **Retention prefs** — prune pcaps/corpus per engagement.
132. **Quota + GC** — cap fuzz artifacts.
133. **API rate-limit** — token bucket per route.
134. **API keys** — scoped tokens.
135. **OIDC login** — lab SSO.
136. **Sandbox profiles** — seccomp/apparmor per job.
137. **Resource caps** — CPU/mem/timeout per job.
138. **Fair-share queue** — priority + preempt.
139. **Remote workers** — nmap/fuzz agents.
140. **Wireguard testbed** — mesh VPN spin-up.
141. **Traffic shaper** — slow/lossy target sim.
142. **DNS sinkhole lab** — malicious-domain replay.
143. **PCAP scrubber** — strip payloads, keep flows.
144. **NetFlow ingest** — flow → assets.
145. **Zeek ingest** — logs → assets.
146. **Suricata EVE ingest** — alerts as leads.
147. **Sigma-hit import** — telemetry → findings.
148. **YARA runner** — over loot/samples.
149. **AV sample scan** — ClamAV + metadata.
150. **Ghidra headless list** — functions/imports only.
151. **capa tags** — capability tags for binaries.
152. **Firmware unpack** — binwalk → SBOM + secrets.
153. **Wardrive import** — BLE/WiFi survey map.
154. **SDR helper** — rtl_sdr capture + metadata.
155. **RFID lab notes** — tag-dump ingest.
156. **USB audit** — authorized peripherals.
157. **IoT cred pack** — printer/cam defaults expansion.
158. **OT banner read** — modbus/s7, read-only.
159. **BACnet/MQTT inventory** — passive subscribe.
160. **CoAP/UPnP probes** — scope-checked.
161. **SIP enumerate** — extensions, opt-in.
162. **Kerbrute user-enum** — opt-in, lab-only.
163. **BloodHound CE wrapper** — collector run.
164. **ADCS audit** — ESC1-8 checks, read-only.
165. **Hound path render** — shortest-path overlay.
166. **Spray charter** — policy infer + safe list.
167. **Hash timeline** — crack → propagate suggest.
168. **Ticket-forge detector** — lab-only signals.
169. **DCSync audit** — replication rights, read-only.
170. **PtH lab** — explicit, lab-only.
171. **LAPS audit** — rotation + exposure.
172. **GPO linter** — offline XML checks.
173. **Sysmon deploy helper** — lab-only.
174. **Velociraptor pack** — collector artifacts.
175. **Osquery import** — fleet inventory.
176. **Wazuh ingest** — agent status.
177. **Nikto→Nuclei dedup** — one finding per vuln.
178. **WhatWeb→CVE link** — tech → CVE auto-link.
179. **Wappalyzer import** — JSON → tech stack.
180. **Headers score** — Lighthouse-style security headers.
181. **Cookie auditor** — Secure/HttpOnly/SameSite.
182. **CORS tester** — origin-reflection, lab-only.
183. **SSRF allowlist tester** — metadata + internal.
184. **SSTI probes** — Jinja/Twig, lab-only.
185. **XXE probes** — oob-safe, lab-only.
186. **Deser gadget index** — hints, no payloads.
187. **SSRF→RCE chain** — config-write → pipeline, lab.
188. **Logic checklist** — IDOR/race/price templates.
189. **Rate-limit map** — 429 probe matrix.
190. **Batching abuse check** — GraphQL batching.
191. **Cache deception check** — path-confusion.
192. **Host-header check** — poisoning, lab-only.
193. **Takeover lead** — CNAME → unclaimed.
194. **Hijack lead** — broken-link target.
195. **JS harvester** — secrets + sourcemaps.
196. **Dictionary editor** — custom fuzz payload sets.
197. **Payload encoder** — b64/url/hex/jwt client-side.
198. **Regex tester** — live highlight for rules.
199. **Nightly autopilot** — cron + webhook recon.
200. **Demo seeder v2** — one-click 5-min talk seed.
