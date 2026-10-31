# h4k achieves host root without sudo — research note (docker group = root)

> Scope: local machine only (`greg@omarchy`, uid 1000). No sudo invoked at any
> step. Purpose: document the path so it can be patched / hardened.
> Date: 2026-10-31.

## TL;DR

`greg` cannot read `/root` directly (`Permission denied`), but `greg` is in the
`docker` group, so any `docker run / exec` works **without sudo** and already
runs as **uid 0**. The `h4k:latest` image has no `USER` directive, so it
defaults to root. Mounting the host filesystem read-only into a throwaway
container exposes the host's root-only files:

```sh
# as greg, no sudo:
whoami            # greg
ls /root          # Permission denied
groups            # greg docker wheel

docker exec h4k_h4k whoami   # root
docker exec h4k_h4k id       # uid=0(root) gid=0(root)

grep -n "^USER" h4k/Dockerfile || echo "no USER line -> defaults to root"

docker run --rm --entrypoint id h4k:latest
# uid=0(root) gid=0(root) groups=0(root)

docker run --rm -v /:/host:ro --entrypoint ls h4k:latest -la /host/root
# total 0
# drwxr-x---  1 root root  44 Oct 28 22:31 .
# drwx------  1 root root  10 Oct 26 19:35 .cache
# ... (same listing greg cannot see directly)
```

That is host-root **read** (and with `:rw` + `chroot` it would be host-root
**write/exec**) with zero sudo invocations.

## Step-by-step (reproducible, no sudo)

1. Confirm non-root on host:
   `whoami; id` → `uid=1000(greg)`, groups `docker,wheel`.
   `ls -ld /root` → `drwxr-x--- root root`; `ls /root` → `Permission denied`.
2. Confirm docker works without sudo:
   `docker ps` lists `h4k_h4k`, `h4k_vulnlab` — no password prompt because the
   caller is in `docker`.
3. Confirm h4k is root by design:
   `docker exec h4k_h4k whoami` → `root`;
   `Dockerfile` contains no `USER` line (verified with grep).
4. Confirm the same image sees host root-only data when the host FS is mounted:
   `docker run --rm -v /:/host:ro --entrypoint ls h4k:latest -la /host/root`
   succeeds where the host `ls /root` fails. `ro` keeps the demo non-destructive;
   the control is the mount, not an exploit.

## Why this works (root cause)

- The Docker daemon runs as root. Membership in the `docker` group is
  **root-equivalent by design**: whoever can talk to `/var/run/docker.sock`
  can ask the daemon (as root) to mount any host path into a container that
  starts as root.
- `h4k/Dockerfile` (`FROM debian:12-slim`) never drops privileges — no
  `USER nobody` — so `ENTRYPOINT ["/entrypoint.sh"]` and every
  `docker exec` land as uid 0. That is normal for a tool container that needs
  `nmap/tcpdump/arp-scan`, but it means any host mount is accessed as root.

This is **not a kernel exploit or a sudo bypass bug** — it is the documented
consequence of `docker` group membership + a root-default image.

## Patching / hardening (for the lab + the host)

1. **Treat `docker` as root.** Only users who should have root may be in the
   group: `sudo deluser greg docker` (requires a privileged admin) removes the
   path entirely.
2. **Least-privilege mounts.** Never add `-v /:/host` (even `:ro`) to compose
   files or helper scripts. The shipped `h4k` compose only mounts the named
   volume `h4k_data → /opt/h4k/data` — keep it that way.
3. **Drop privileges in-image where possible.** Tool stages that need raw
   sockets (`nmap -sS`, `tcpdump`) need `NET_RAW`; the API/UI itself could run
   as a non-root `USER h4k` with only needed `cap_add:` entries, so a
   container breakout starts from less.
4. **Rootless docker / user namespaces.** `--userns-remap` or rootless mode
   maps container uid 0 to an unprivileged host uid, closing the
   mount-equals-host-root shortcut.
5. **Socket hygiene.** `/var/run/docker.sock` must never be mounted inside
   `h4k_h4k` / `vulnlab` — that would let any RCE in the lab become host root
   instantly.
6. **Audit.** `docker ps`, `docker inspect … .Mounts`, and `groups <user>`
   are the three checks: who can talk to the daemon, what host paths are
   mounted, and what user the image runs as.

## Evidence captured

- `docker exec h4k_h4k whoami` → `root`, `id` → `uid=0(root)`.
- Host `ls /root` → `Permission denied` vs containerized
  `ls -la /host/root` → full listing (same inode data, see shell transcript).
- `h4k/Dockerfile:1-136` — `FROM debian:12-slim`, no `USER` line.
- No `sudo` process invoked: all commands above run as `greg` via the
  `docker` group socket.
