# Engagement finding: 192.168.1.26 (lab Pi)

**Target:** `192.168.1.26` — a Raspberry Pi ("pi.hole") running a home media /
DNS stack. Authorized lab engagement; all actions below were taken with the
h4k platform from the Docker stack.

**Date:** 2026-10-29 · **Operator:** h4k (automated) · **Scope:** `192.168.1.0/24`

---

## 1. What h4k found

`POST /api/scan` (full depth, via `db_nmap` in the container) + NSE probes:

| Port | Service | Version |
|---|---|---|
| 21 | FTP | vsftpd 3.0.3 |
| 22 | SSH | OpenSSH 9.2p1 Debian-2+deb12u10 |
| 53 | DNS | Pi-hole (generic DNS response) |
| 443 | HTTPS | Pi-hole admin |
| 8080 | HTTP | Pi-hole v6 admin (CherryPy) |
| 8081 | HTTP | **SABnzbd 4.5.0** (CherryPy 18.8.0) |
| 8096 | HTTP | **Jellyfin 10.8.13** |
| 7878 | HTTP | **Radarr** |
| 8686 | HTTP | **Lidarr** |
| 8989 | HTTP | **Sonarr** |
| 9696 | HTTP | **Prowlarr** |
| 6767 | HTTP | **Bazarr** |
| 9091 | HTTP | **Transmission 3.00 (RPC)** |
| 11435 | HTTP | **Ollama 0.20.5** |
| 32400 | HTTPS | **Plex 1.43.5.11079** |
| 5201 | TCP | iperf3 |

h4k's CVE matcher flagged `CVE-1999-0527` / `CVE-2011-2523` (vsftpd backdoor)
from the FTP service name alone.

## 2. Credential attacks (all failed)

| Target | Combinations | Result |
|---|---|---|
| SSH (22) | 25 060 (nmap 5 k password list × 5 users) | none |
| SSH (22) | 640 (service accounts: `debian-transmission`, `plex`, `sonarr`, …) | none |
| FTP (21) | 30 078 | none |
| Pi-hole v6 `/api/auth` | full 5 007-word list | none |
| Radarr / Lidarr / Prowlarr `/api/v3/auth/local` | 9 users × 1 200 passwords | none |
| Jellyfin `/Users/AuthenticateByName` | 9 × 49 | none |
| SABnzbd API + web login | key + password | none |

## 3. CVE-driven exploitation (correctly refused)

Run through h4k → Metasploit RPC:

* `exploit/unix/ftp/vsftpd_234_backdoor` → *"Cannot reliably check
  exploitability"* / *"No session created"*. The banner says **vsftpd 3.0.3**;
  the backdoor only exists in 2.3.4. The manual smiley-user login
  (`USER ftpuser:)`) confirms it: `530 Login incorrect`, port 6200 closed.
* `exploit/unix/http/pihole_blocklist_exec` → fails; the box runs **Pi-hole
  v6** (the module targets ≤ 4.4) and the API demands a session.

**The CVE match is a false positive**: h4k matched the *service name* `ftp`,
not the banner. Worth fixing in the matcher (see §6).

## 4. The real finding: unauthenticated Transmission RPC → arbitrary file write

`http://192.168.1.26:9091/transmission/rpc` answers with **no authentication**
(`session-get` returns the daemon's configuration, including `download-dir`
and `config-dir`).

That alone is a misconfiguration, but it becomes an **arbitrary file write**
primitive:

1. `session-set` arms any daemon setting (script hooks, DHT/µTP, dirs).
2. `torrent-add` accepts a `.torrent` **by URL** — the daemon fetches it from
   the attacker.
3. The attacker serves a one-piece torrent whose payload is arbitrary bytes;
   the daemon writes it to any directory it can write.

Verified writable by the daemon account:

* `/home/operator/Downloads/`
* `/var/lib/transmission-daemon/.config/transmission-daemon/` (its own config!)
* `/var/lib/transmission-daemon/Downloads/`

Everything else tested (`/etc/cron.d`, `/usr/local/bin`, `/root/.ssh`,
`/home/operator/.ssh`, `/var/lib/plexmediaserver`) is correctly refused with
`Permission denied`.

### Making the transfer happen (custom tooling)

Transmission ignores tracker peers it can't reach, refuses `x.pe`, prefers
µTP, and wants a **bencoded (BEP 48)** tracker response. `scripts/torrent_seeder.py`
and `scripts/torrent_tracker.py` implement exactly that:

```
attacker                                  victim (pi.hole)
  tracker  :6883  ── announce ─────────▶  Transmission (9091)
  seeder   :6882  ◀── peer (TCP)  ──────  "give me piece 0"
            └──── 92 bytes of our data ──▶ written to disk
```

Details that cost real debugging time (all fixed in the scripts):

| Gotcha | Fix |
|---|---|
| tracker must answer **bencoded** (BEP 48), not JSON/compact | `TRACKER_STYLE=bencode` |
| client prefers **µTP** | `session-set {"utp-enabled": false}` |
| client ignores **DHT** peers | `session-set {"dht-enabled": false}` |
| handshake starts with a **length byte** | compare `header[1:20]` |
| piece message length prefix is **9 + len**, not `1 + 9 + len` | fixed in the seeder |
| message ids: bitfield = **5**, unchoke = **1**, piece = **7** | fixed in the seeder |
| torrent names are **sanitised** (`/` → `_`) — no path traversal | so writes are flat files only |

## 5. Why it stopped short of a shell

Transmission 3.00's `script-torrent-done` hook **never fires** on this host —
verified with six different command forms (`/bin/sh -c "…"`, bare
`curl <url>`, `/usr/bin/python3 -c "…"`, `/bin/bash /home/operator/Downloads/x.sh`,
a script file written by the same file-write primitive) and with the torrent
forced into the "finished" state (`seedRatioMode=1`, `seedRatioLimit=0`).
The hook is armed in memory and on disk (`session-set` → `settings.json`) and
still does not execute.

Other routes were closed off:

* **SSH key drop** — `~/.ssh` is not writable by the daemon account, and even
  where a `.ssh` directory exists, `sshd`'s `StrictModes` rejects a file owned
  by a different user.
* **Path traversal in the torrent name** — Transmission sanitises `/` to `_`.
* **cron / `authorized_keys` in another user's home** — not writable.

So the outcome is: **unauthenticated remote write as the `transmission` service
account**, not a root/greg shell.

## 6. Follow-ups for h4k itself

1. **CVE matching must be banner-aware** — it flagged the vsftpd backdoor on a
   vsftpd **3.0.3** banner (service-name match only).
2. **The engineer's `find_exploits()` was broken** (fixed in this session: the
   module catalogue lives in `modules.exploits`, not `module_types`).
3. **Auxiliary modules could not run** (fixed: the module type now follows the
   path, and `module.options`/`module.execute` are read over raw RPC).
4. **Attack requests could not pass module options** (fixed: `options` on
   `AttackRequest`, filtered by the module's own option list).
5. New lab tooling in `scripts/`: `transmission_rpc.py`, `torrent_seeder.py`,
   `torrent_tracker.py`.

## 7. Remediation on the Pi (owner's action)

1. Enable RPC auth: `settings.json` → `"rpc-authentication-required": true`
   and set `rpc-username` / `rpc-password` (or bind RPC to localhost only).
2. Firewall `9091` from the LAN.
3. Run the Transmission daemon as its own unprivileged user (it is) and keep
   `download-dir` outside any directory other services read.
4. Set a strong password on every web admin (Pi-hole, SABnzbd, Plex, *arr,
   Jellyfin) — none of them accepted any common credential, but the services
   are all reachable from the LAN.
