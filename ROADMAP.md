# h4k — Roadmap

Prioritized by **wow-factor for a class demo × real-world value × effort**. Each
item is a self-contained, live-demonstrable increment on the current release.

---

## Tier 1 — polish & airtightness (small effort, big payoff)

- [ ] **Sanitizer-first everywhere** — surface ASan/UBSan flags in *every*
      finding (fuzz + SAST), not just line numbers, so each one shows a clean
      crash/error trace.
- [x] **True crash minimization** — wrap libFuzzer `-minimize_crash=1` /
      `afl-tmin` behind `/api/fuzz` so a crash auto-reduces to the smallest
      repro, then feed it straight into triage. ("Here's the exact 12-byte
      trigger.")
  (done: OSS-Fuzz runner minimizes crash artifacts server-side)
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
- [ ] **Local TLS interception lab** — mkcert + local CA so the fuzzer/SAST can
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

## Infra / shipping

- [ ] **Ollama sidecar in compose** — run Ollama in its own container on a
      non-standard port; `OLLAMA_BASE_URL` already makes this a config change.
- [ ] **CI**: GitHub Actions running lint + tests on push (reproducible quality
      gate for the class).
- [ ] **Release packaging** — tagged image + one-line `docker run` for classmates.

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
