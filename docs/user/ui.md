# UI guide

The console is a **kill-chain operator console** built around the phases you
actually run in a CTF: **Discover → Recon → Exploit → Pivot → Persist → Score**.
The status bar carries the engagement scope picker, health pills, and loot
counters; the next-action strip floats the single best recommended move; each
workspace button shows a live count badge as you progress down the chain.

Design rules: no gamification, no webfonts (works offline on a lab network),
dark-first with a light theme, keyboard-driven, every control has a
`data-testid` so the Selenium suite drives what a human does.

---

## Status bar

| Element | Meaning |
|---|---|
| scope picker | Lists engagements. The selected one constrains every aggressive action. `scope: none` means recon only, nothing recorded. |
| `msf-status` | Metasploit RPC state (up/down). |
| `cap-status` | Tool readiness (`caps: N tools`). |
| `autoscan-status` | Passive auto-scan state (`scan running/idle`). |
| `flag-counter` / `host-counter` | Captured flags / discovered hosts. |
| log / ⌘ / ◐ / ⟳ | Activity drawer, command palette, theme, session reset. |

## Ops rail (right side, wide screens)

A persistent sidebar next to the workspace: **Session** (active scope id,
host/service/vuln/shell/cred/flag counts, refreshed on every poll) and
**Activity** (a live mirror of the last 40 log lines — the full log lives
in the drawer). It stacks below the workspace under 900 px.

## Next strip

`next` ranks the single best recommended action for the engagement
(attack paths first, then exploits, default creds, recon, fuzz). `▶`
runs the top recommendation; `↻` refreshes. Firing a queue entry runs
the real action.

---

## Phases (keys 1–6, j/k/h/l to move)

### 1. Discover — find targets

A **Workflow** strip tracks scope → scan → fingerprint → win (click a step
to jump there). Then: scope summary (what you are allowed to touch),
target input + mode/depth, Scan, Neighbors (ARP), passive auto-scan state
+ toggle. Results flow into Recon.

### 2. Recon — fingerprint, vulns

* **Services** — fingerprinted open ports with a per-row exploit shortcut.
* **Likely vulnerable** — banner-aware CVE hits with severity and a fire button.
* **Web assessment** — nikto scan + gobuster content discovery for one web
  surface you own.

### 3. Exploit — win the first shell

* **Attack queue** — ranked next moves from the next-move engine, each with a fire button.
* **Autopilot** — discovery → fingerprint → CVE → password attacks → exploits. Requires an active scope. Live log + host table.
* **Password attacks** — services worth trying, driven by verified cred families.
* **Fuzz lab** — lab-only black-box fuzzing of a service you own, with crash reproduce output.
* **Container surfaces** — inventory Docker/containerd/kubelet runtimes,
  then fuzz one surface you own (job-based, candidates stream in).

### 4. Pivot — turn one shell into many

* **Shells** — live sessions with a session console. Output is scanned for flag-shaped secrets.
* **Credential ledger** — verified credentials only. Propagation plan + Execute replays them across in-scope services.
* **Route map** — local interfaces and routes for pivot planning (read-only).
* **Interrogate** — enumerate DBs/configs/APIs on a compromised host for flag-shaped strings; container-escape check (read-only detect).
* **Try local root** — one-shot passwordless assessment (userns uid 0,
  docker-group read, SUID/caps/gates/CVE posture). Read-only, no password.
* **Fire TV** — recon / pair / state / apps / screenshot for an Android TV
  you own. Pairing needs the on-TV code; shell-class actions need approval
  on the TV.

### 5. Persist — hold the win

A checklist, not implants: live sessions, banked credentials (your re-entry
keys), captured flags. **Re-enter** replays verified creds to get back in
after a lost shell. No fake persistence is claimed: if a shell dies, creds
are how you return.

### 6. Score — flags, objective, writeup

* **Flags** — captured flags (value, host, auto/manual). Add manually or Scan output (auto-detect in console output).
* **Crown jewels → attack paths** — declare objectives, Compute paths (or
  Flag paths for captured flags), read score/hops/vulns.
* **ATT&CK & detection** — findings mapped to techniques with telemetry.
* **Report** — machine-generated markdown writeup, Download MD.

---

## Command palette (`Ctrl+K`, filters as you type, Enter runs the first hit)

scan · neighbors · fingerprint · autopilot · nikto · gobuster · firetv ·
container-fuzz (`cfuzz`) · persist · score · theme · clear.

## Keyboard

| Key | Action |
|---|---|
| `Ctrl+K` | Command palette |
| `Ctrl+Enter` | Launch scan (Discover) |
| `T` | Toggle theme |
| `1`–`6` | Switch phase |
| `j` / `k` / `h` / `l` | Next / prev phase |
| `Esc` | Close palette / drawer |

---

## Accessibility & responsiveness

* Visible labels on every control; focus outlines preserved.
* The page never scrolls sideways: cards stack, tables scroll inside their
  card (`.tbl-wrap`), the two-column workspace + rail collapses to one column
  under 900 px, the workspace strip scrolls, and the status bar sheds chrome
  as width shrinks (scope goes full-width ≤900px, pills collapse to dots
  ≤640px).
