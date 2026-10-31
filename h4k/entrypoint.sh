#!/usr/bin/env bash
# h4k entrypoint: bring up the Metasploit database + tor + msfrpcd + the API
# on 0.0.0.0:3137.
#
# The Metasploit database is the fragile part of the boot: `msfdb` manages its
# own postgres cluster, and the RPC daemon only exposes db.* methods once it
# has actually loaded the database. If the daemon starts before the cluster is
# reachable it silently answers "Database Not Loaded" -- and then db_nmap
# finds nothing, which looks exactly like "the scan tool is broken".
#
# So: start the cluster, wait for it, then start the daemon, then *verify* the
# daemon can see the database and restart it if it cannot.
set -euo pipefail

MSF_DB_PORT="${MSF_DB_PORT:-5433}"

echo "[h4k] starting postgres..."
service postgresql start >/dev/null 2>&1 || true

# Metasploit DB must be initialized as a non-root user.
# Create a dedicated 'msf' system user if it does not already exist.
if ! id -u msf >/dev/null 2>&1; then
  useradd -m -s /bin/bash msf
  usermod -aG postgres msf
  chown -R msf:msf /home/msf
  chown -R msf:msf /root/.msf4 2>/dev/null || true
fi

echo "[h4k] initializing msf database (as user msf, port ${MSF_DB_PORT})..."
runuser -u msf -- bash -lc "msfdb init --db-port ${MSF_DB_PORT}" \
  >/tmp/msfdb_init.log 2>&1 || true

# Wait for the cluster to accept connections. `msfdb init` normally leaves it
# running, but a restart or a slow start must not race the daemon.
db_up() {
  (echo > /dev/tcp/127.0.0.1/"${MSF_DB_PORT}") 2>/dev/null
}
for i in $(seq 1 30); do
  if db_up; then
    echo "[h4k] metasploit database is listening on ${MSF_DB_PORT}."
    break
  fi
  sleep 1
done

# msfrpcd and msfconsole (via db_nmap) run as root, so give root the DB config too.
mkdir -p /root/.msf4
rm -f /root/.msf4/database.yml
if [ -f /home/msf/.msf4/database.yml ]; then
  cp /home/msf/.msf4/database.yml /root/.msf4/database.yml
  chmod 600 /root/.msf4/database.yml
else
  echo "[h4k] WARNING: no Metasploit database config was created." >&2
  echo "[h4k]          Metasploit will run without a DB (db_nmap finds nothing)." >&2
  tail -n 20 /tmp/msfdb_init.log >&2 || true
fi

echo "[h4k] starting tor..."
service tor start >/dev/null 2>&1 || (tor --runasdaemon=1 >/dev/null 2>&1 &)

start_msfrpcd() {
  msfrpcd -a "${MSF_HOST}" -p "${MSF_PORT}" -U msf -P "${MSF_PASSWORD}" -S true -f \
    >/tmp/msfrpcd.log 2>&1 &
}

echo "[h4k] starting msfrpcd on ${MSF_HOST}:${MSF_PORT}..."
start_msfrpcd

# give msfrpcd a moment to bind
for i in $(seq 1 20); do
  if (echo > /dev/tcp/127.0.0.1/"${MSF_PORT}") 2>/dev/null; then
    echo "[h4k] msfrpcd is up."
    break
  fi
  sleep 1
done

# Does the daemon actually have the database loaded? Ask it over RPC.
db_loaded() {
  MSF_PASSWORD="${MSF_PASSWORD}" MSF_HOST="${MSF_HOST}" MSF_PORT="${MSF_PORT}" \
  python3 - <<'PY' >/dev/null 2>&1
import os
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient(
    os.environ.get("MSF_PASSWORD", ""),
    server=os.environ.get("MSF_HOST", "127.0.0.1"),
    port=int(os.environ.get("MSF_PORT", "55553")),
    ssl=False,
)
status = client.db.status
raise SystemExit(0 if isinstance(status, dict) and status.get("db") else 1)
PY
}

if db_loaded; then
  echo "[h4k] metasploit database: connected"
else
  echo "[h4k] metasploit database not loaded yet - restarting msfrpcd..." >&2
  # Kill the old daemon (no pkill in the slim image) and start a fresh one.
  for p in /proc/[0-9]*; do
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)
    case "$cmd" in
      *msfrpcd*) kill -9 "${p#/proc/}" 2>/dev/null || true ;;
    esac
  done
  sleep 2
  start_msfrpcd
  for i in $(seq 1 30); do
    if db_loaded; then
      echo "[h4k] metasploit database: connected (after restart)"
      break
    fi
    sleep 2
  done
  if ! db_loaded; then
    echo "[h4k] WARNING: metasploit database is NOT connected (db_nmap finds nothing)" >&2
    tail -n 10 /tmp/msfrpcd.log >&2 || true
  fi
fi

echo "[h4k] starting API on 0.0.0.0:${API_PORT}..."
exec python3 -m uvicorn api.main:app --host 0.0.0.0 --port "${API_PORT}"
