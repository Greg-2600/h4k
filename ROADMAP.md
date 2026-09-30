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
- [x] **AI hookup toggle in the UI** — surface Ollama reachability + model picker
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

- [ ] **Attack paths to objectives** — let the operator declare crown jewels
      (a DC, a file server, `db-prod-01`) and compute *paths* to them, so a
      2.0 info-leak that pivots to the DC outranks a 9.8 on an isolated box.
      Needs the engagement graph above; this is the missing deliverable.
- [ ] **ATT&CK technique IDs** — map every action/finding to a technique so the
      output speaks the defender's language. Cheap once paths exist.
- [ ] **Detection guidance** — per technique, what telemetry a defender would
      have seen (log source, event ID). Worth more to a client than the vuln list.

## CTF / Live-target enhancements (added during 192.168.1.13 engagement)

- [ ] **Container escape module** — exploit CAP_SYS_PTRACE / CAP_DAC_OVERRIDE /
      host mounts for breakout (ptrace sandbox escape, cgroup release_agent,
      mount namespace traversal). Integrate with deepattack as "privesc" step.
- [ ] **Lateral movement / network pivot** — ARP + route discovery + SSH/SMB
      relay + proxy chains through compromised hosts. Auto-build chisel/sshuttle
      tunnels through verified creds.
- [ ] **Database interrogation** — enumerate internal APIs (zhc3, Ollama, CAD
      worker) via REST/GraphQL; extract flags from DBs, env vars, config files.
      Treat every open HTTP API as a potential data source.
- [ ] **Advanced fuzzing for container surfaces** — fuzz Docker API, containerd
      gRPC, kubelet, CAD worker endpoints for RCE/DoS.
- [ ] **Attack path graph to flag** — compute minimal path from foothold to flag
      (container escape → host → other containers → DB → flag). Show ATT&CK
      chain.

## Infra / shipping

- [x] **Ollama sidecar in compose** — run Ollama in its own container on a
      non-standard port; `OLLAMA_BASE_URL` already makes this a config change.
  (done: compose `ollama-sidecar` service on `127.0.0.1:11435`, `--profile llm`)
- [x] **CI**: GitHub Actions running lint + tests on push (reproducible quality
      gate for the class).
  (done: `.github/workflows/ci.yml` runs `make lint` + `make coverage` on push/PR)
- [x] **Release packaging** — tagged image + one-line `docker run` for classmates.
  (done: `scripts/release.sh <ver>` builds/tags/pushes and prints the one-liner)

## Evaluated & rejected

- **ExploitGym** (`sunblaze-ucb/exploitgym`) — not adopted. It's a CyberGym-style
  Docker-in-Docker eval rig whose only agent backends (Codex / Claude Code /
  Gemini CLI) all require a cloud LLM API key; there is no local/no-key path,
  and it needs Python 3.12+ and per-task target images + a squid firewall +
  controller. It also clashes with the project's local-first, no-weaponization
  stance. The exploit-first AI loop (minimal trigger → patch → verify) already
  demonstrates the same "AI turns a finding into a confirmed attack" idea
  locally via Ollama.

---

## Suggested order for a 10-minute class demo

1. **Crash → minimize → patch** (Tier 1): fuzz vulnlab → ASan hit → minimized
   repro → patch candidate → re-fuzz clean.
2. **Custom Semgrep rule** (Tier 2) matching a pattern you invent live.
3. **SCA on the fixture repo** (Tier 2) → instant CVE hits from the lockfile.
4. **AI root-cause + patch** via local Ollama (Tier 1/3), noting the ethics gate.

**h4k**, out.
