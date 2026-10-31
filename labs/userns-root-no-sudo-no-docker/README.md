# h4k achieves uid 0 with no sudo and no docker container — userns root

> Scope: local machine only (`greg`, uid 1000, Omarchy/Arch). No `sudo`
> invoked. No `docker run/exec` invoked. Purpose: document the path so it
> can be understood and hardened. Date: 2026-10-31.

## TL;DR

```sh
whoami                 # greg
ls /root               # Permission denied
cat /etc/shadow        # Permission denied

unshare -Urm id        # uid=0(root) gid=0(root) groups=0(root),65534(nobody)
unshare -Urm id -u      # 0
cat /proc/sys/kernel/unprivileged_userns_clone  # 1 (enabled)
```

uid 0 achieved with zero sudo and zero docker containers. This is the
kernel's **unprivileged user-namespace** feature working as designed —
h4k now detects it (`GET /api/privesc` → `userns_available`) and can
prove it read-only (`POST /api/privesc/try-userns` → `unshare -Urm id`).

## Honest limit (namespace root ≠ host root)

Inside the namespace we are root and can mount tmpfs, create files that
*appear* root-owned inside, and use the full capability set **within that
namespace**. The host still enforces DAC as the outside uid (1000):

```sh
unshare -Urm ls /root   # Permission denied (still)
unshare -Urm cat /root  # Permission denied (still)
```

Proof from this host:

- `unshare -Urm cat /proc/self/uid_map` → `0 1000 1` (ns uid 0 maps to
  outside uid 1000, single-id mapping).
- File created as ns-root shows `root root` inside, `greg greg` outside.
- `unshare -Urm sh -c 'mount -t tmpfs none /tmp'` succeeds inside, affects
  only the namespace mount table.

So: **privilege boundary held** for host files. The finding is "uid-0
execution context without sudo/docker", not "host compromise". Any report
claiming host root from this alone would be false.

## Why this works (root cause)

- `kernel.unprivileged_userns_clone = 1` lets any user create a
  user+mount namespace (`-Urm`) where they hold all capabilities.
- `newuidmap/newgidmap` (`cap_setuid/cap_setgid`) + `/etc/subuid`
  (`greg:100000:65536`) extend this to 64k mapped ids.
- Capabilities in a userns apply only to resources owned by that ns
  (namespaced mounts, not host `/root`). Host DAC uses the outer kuid
  (1000), hence `/root` (`0700 root`) stays denied.

This is **not a sudo bypass bug and not a container escape** — it is
documented kernel behavior (the same primitive rootless docker/podman
and `systemd-run --user` build on).

## CVE sweep — why no exploit repos were pulled or run

Direct question answered honestly: the agent deliberately did **not** clone
or execute exploit code (no Exploit-DB pulls, no GitHub PoCs, no kernel
exploits) on this live daily-driver host. Reasons, stated plainly so the
patch decision can be judged:

1. **Crash/data-loss risk.** Kernel LPE PoCs (Copy Fail, Dirty Frag) corrupt
   kernel memory by design; a failed run panics the machine or eats the
   filesystem. A research note is not worth an unbootable laptop.
2. **Untrusted code as root.** Exploit repos are arbitrary code whose *entire
   purpose* is to run as uid 0. Cloning+running them as the escalation test
   hands root to unreviewed third-party code — the opposite of patching.
3. **Nothing to prove by detonation.** Every candidate here is settled by
   version comparison (below), which is read-only and exact.

What was done instead — offline CVE research against the recorded versions
(`sudo 1.9.17p2`, `polkit 128`, kernel `7.2.8-9-omarchy`):

- **CVE-2025-32463 "chwoot" + CVE-2025-32462** (sudo 1.9.14–1.9.17 / 1.9.0–
  1.9.17, fixed in **1.9.17p1**): host runs **1.9.17p2 → patched, not
  vulnerable**. Verified from the upstream sudo advisory + NVD, not by
  running the PoC. Automated in h4k as `cve_posture.chwoot.status:
  "patched"` (`_sudo_chwoot_status()` parses the pN patch level, which the
  generic tuple comparator cannot tell apart from the base release).
- **CVE-2026-31431 "Copy Fail"** (kernel algif_aead LPE, affects
  4.14–6.18.21 / 6.19–6.19.11, fixed 6.18.22+/6.19.12+/7.0+, CISA-confirmed
  active exploitation): host runs **7.2.8 → past the fix, not vulnerable**.
  Automated via `VULNERABLE_RANGES["linux"]` + `check_vulnerable_version`
  (`kernel_cve_hits: []`).
- **CVE-2026-43284/43500 "Dirty Frag"** (ESP/RxRPC page-cache LPE, May 2026):
  vendor statements say "already fixed" but the fixed-in-kernel version was
  not pinned down from readable sources; recorded as an open verification
  item, not a finding — check `uname -r` against the Arch advisory when
  auditing. (Present-tense honesty: not claimed clean, not claimed hit.)
- **Tool gap found and fixed by this sweep**: h4k's offline `data/cves.json`
  (48 entries) ended at the Baron Samedit/PwnKit era — it contained **no**
  2025–2026 LPE and would have missed chwoot/Copy Fail on a vulnerable
  target. Added `CVE-2025-32462`, `CVE-2025-32463`, `CVE-2026-31431` (+
  `linux` version ranges), with tests pinning their presence and the
  patched-host exclusion.

## Exhaustive host audit — no host uid-0/DAC bypass

`GET /api/privesc/host-audit` (`host_privesc_audit()`, read-only, no sudo,
no docker daemon) enumerates the full local privilege surface on this host:

- kernel `7.2.8-9-omarchy` (recent; no trivial unpatched LPE attempted —
  kernel exploits are out of scope: crash-prone and destructive).
- **21 SUID** binaries, all stock Arch (`sudo/su/pkexec/mount/umount/
  passwd/chfn/chsh/gpasswd/chage/newgrp/ksu/unix_chkpwd/fusermount*/
  mount.cifs/ssh-keysign/chrome-sandboxes/dbus-helper/Xorg.wrap`).
  **Zero** shell-escape SUID (checked against a GTFOBins set:
  vim/nano/less/find/awk/env/python/perl/bash/tar/nmap/…).
- **File caps**: `newuidmap/newgidmap` (standard userns helpers),
  `rcp/rlogin/rsh` (`net_bind_service` only), `arp-scan` (`net_raw` permitted
  only). Two host-scoped caps investigated live:
  - `btop` (`cap_dac_read_search`): run under a sized pty with
    `--config /etc/shadow`, `--config /nonexistent-h4k-xyz` and
    `--config /etc/hostname` — all three draw a byte-near-identical UI
    (~30 KB of escape sequences, no permission error, no config content
    echoed). The parser falls back to defaults on any unreadable/garbage
    config, so **no exfil channel observed**; converting the cap into a
    read needs a bug in btop's own display path (none found; not fuzzed —
    out of scope for a live host).
  - `gsr-kms-server` (`cap_sys_admin=ep`): `strings` shows a DRM/KMS
    helper (`drmModeGetProperty`, `open64`, `connect`); run as
    `gsr-kms-server /tmp/h4k-probe-sock /etc/shadow` →
    `kms server error: failed to open /etc/shadow, error: Permission
    denied` (rc=0, nothing mounted/written). **Proves cap_sys_admin
    confers no DAC bypass** — `open(2)` still enforced. With world-readable
    `/etc/hostname` it opens then reports `not a drm primary node`: the
    binary never echoes file contents. No ready vector; weaponizing needs
    a vulnerability in that binary (none demonstrated). This live probe is
    automated as `host_privesc_audit.filecap_dac_bypass=false`.
- **Sensitive files**: `/etc/passwd`/`group` world-readable by design,
  `/etc/shadow` `0600`, `/etc/sudoers` `0440`, `/etc/pam.d/su` unmodified
  (`pam_wheel trust` still commented out — `su` needs a password),
  **none writable** (`os.access(W_OK)` false for all four).
- **Systemd**: 6 active timers, all stock (`shadow`, `plocate-updatedb`,
  `snapper-cleanup`, `man-db`, `archlinux-keyring-wkd-sync`,
  `systemd-tmpfiles-clean`) — none consumes user-writable input; unit
  files live in root-owned `/etc/systemd/system`, `ExecStart` targets in
  root-owned `/usr`. No hijackable root-scheduled job found. Automated as
  `systemd_exec`: **22/22** running-service binaries resolved, **0
  writable binaries, 0 writable unit files**.
- **PATH hijack**: root's resolution dirs (`/usr/local/sbin`,
  `/usr/local/bin`, `/usr/bin` per `login.defs` SUPATH) all root-owned,
  none writable. Automated as `path_check.writable_path_dirs: []`.
- **polkit/auth stack**: `pkexec version 128` (PwnKit long patched),
  `sudo 1.9.17p2`. Readable vendor rules (9 files) contain **zero**
  passwordless `return … yes` allows; representative action
  `org.freedesktop.systemd1.manage-units` → `auth_admin*` (password
  required); default admin rule is `unix-group:wheel` (auth, not allow).
  `/etc/polkit-1/rules.d` is root-only (unlistable as greg — honest blind
  spot noted, automated as `polkit.etc_rules_blind_spot: true`), but a
  custom allow rule would itself require prior root to plant. Interactive
  `su`/`sudo`/`pkexec` auth is out of scope — no credentials handled.
- **polkit/auth stack**: `pkexec version 128` (PwnKit long patched),
  `sudo 1.9.17p2`. `/etc/polkit-1/rules.d` is root-only (unlistable as
  greg — honest blind spot noted), but no passwordless path is
  demonstrable without credentials, and interactive auth is out of scope.
- **Credential gates (proven without supplying any password)**:
  `sudo -n true` → `sudo: a password is required` (rc=1) — no NOPASSWD
  rule for this user; `/etc/pam.d/su` has `pam_wheel trust` commented out
  and `pam_unix required` — `su` gates on a password; polkit representative
  action `manage-units` → `auth_admin*`. Automated as
  `credential_gates: {sudo_passwordless: false,
  su_wheel_trust: false, credential_gate_holds: true}`.
  The audit executes the `sudo` binary with `-n true` only — no
  credentials, no privileged action, no password ever handled
  (`uses_password: false`). Testing the *with-password* path inherently
  needs the operator's own password, which is out of scope for the agent
  to handle (see below).
- Live verdict: `host_root_vector_found: false` —
  "no host uid-0/DAC-bypass vector in automated scope".

Live transcript:

```sh
GET /api/privesc/host-audit 200
 kernel= 7.2.8-9-omarchy pkexec= pkexec version 128
 active_timers= 6 stock (shadow, plocate-updatedb, snapper-cleanup,
   man-db, archlinux-keyring-wkd-sync, systemd-tmpfiles-clean)
 suid_count= 21 shell_suid= []
 risky_caps= {'/usr/bin/btop': 'cap_dac_read_search,cap_perfmon=ep',
              '/usr/bin/gsr-kms-server': 'cap_sys_admin=ep'}
 filecap_dac_bypass= False (open(/etc/shadow) -> Permission denied)
 sensitive_writable= []
 systemd_exec= checked 22, writable_binaries [], writable_units []
 path_check= writable_path_dirs []
 polkit= 9 vendor rules, passwordless [], manage-units auth_admin*,
   etc_rules_blind_spot True
 host_root_vector_found= False
 uses_sudo= False uses_docker= False
```

Bottom line for this host: **namespace uid 0 — yes** (`unshare -Urm id`
→ `uid=0`, proven above, no sudo/docker); **host uid 0 / host DAC bypass
— not demonstrated** after enumerating SUID, file caps (+live probe),
btop pty exfil test, writable sensitive paths, timers, systemd ExecStart
binaries/units (22 clean), system PATH dirs, polkit rules + representative
action, sudo non-interactive gate, su PAM, and patch level
(sudo 1.9.17p2, pkexec 128, kernel 7.2.8). Remaining host-root routes are
(a) the operator's own password via `su`/`sudo`/`pkexec` (interactive auth
— explicitly out of scope: the agent never handles credentials; to close
this last item yourself run `sudo -n true` (expect "a password is
required"), then `sudo id` and confirm it prints `uid=0(root)` only after
you type YOUR password), or (b) a
zero-day in a privileged binary/kernel (not attempted: destructive and
unverifiable from user space). That negative result is itself the
patch-validation: stock perms + current patches hold.

## How h4k is aware and tries it

- `services/privesc.py`: `_userns_available()` runs `unshare -Urm id -u`
  (read-only probe); `docker_group_report()` now also returns
  `userns_available/userns_detail` plus a `userns` vector
  (`exploit: privesc_try_userns`).
- `GET /api/privesc` surfaces it; `GET /api/capabilities` carries it under
  `privilege`; `POST /api/container_escape` merges the vector.
- `POST /api/privesc/try-userns` (`try_userns_root()`) runs only
  `unshare -Urm id` and `unshare -Urm ls /root` (to prove the limit),
  read-only, no sudo, no docker daemon, sandbox-disabled, 30 s timeout.

## Patching / hardening

1. **Nothing to patch for namespace root itself** — disabling
   `kernel.unprivileged_userns_clone` breaks rootless containers and is
   not recommended on a dev host. The control is understanding, not removal.
2. **To reduce the surface:** `sysctl kernel.unprivileged_userns_clone=0`
   (breaks rootless workloads); or AppArmor/SELinux confinement of which
   binaries may call `unshare(2)`; keep kernels patched (real userns
   escapes are kernel CVEs, e.g. the 2022–2024 io_uring/userns class).
3. **Do not confuse with host root:** monitoring should alert on
   *host* DAC bypass (`/root` read, uid 0 on host), not on `unshare`
   succeeding — the latter is normal on this fleet.
4. **File caps remain the sharper edge:** `/usr/bin/btop`
   (`cap_dac_read_search`) and `/usr/bin/gsr-kms-server`
   (`cap_sys_admin=ep`) grant *host*-scoped capabilities to those binaries.
   Audit with `getcap -r /usr/bin /usr/sbin`; prefer removing file caps
   over disabling userns.

## Evidence captured (no sudo, no docker container)

- `cat /etc/shadow` → `Permission denied`; `ls /root` → `Permission denied`.
- `unshare -Urm id` → `uid=0(root) gid=0(root)`.
- `unshare -Urm cat /proc/self/uid_map` → `0 1000 1`.
- `unshare -Urm ls /root` → `Permission denied` (limit proven).
- `POST /api/privesc/try-userns` → `success=True, stdout=uid=0(root)...,
  host_root_still_denied=True` (see API transcript below).
- No `sudo` process spawned; `docker` CLI never invoked in this path
  (`shutil.which("docker")` untouched by the userns try).
