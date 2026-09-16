#!/usr/bin/env bash
# h4k entrypoint: bring up postgres + msfdb + tor + msfrpcd + the API on 0.0.0.0:3137
set -euo pipefail

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

echo "[h4k] initializing msf database (as user msf)..."
runuser -u msf -- bash -lc 'msfdb init >/tmp/msfdb_init.log 2>&1 || true'

# msfrpcd and msfconsole (via db_nmap) run as root, so give root the DB config too.
mkdir -p /root/.msf4
rm -f /root/.msf4/database.yml
cp /home/msf/.msf4/database.yml /root/.msf4/database.yml 2>/dev/null || true

echo "[h4k] starting tor..."
service tor start >/dev/null 2>&1 || (tor --runasdaemon=1 >/dev/null 2>&1 &)

echo "[h4k] starting msfrpcd on ${MSF_HOST}:${MSF_PORT}..."
msfrpcd -a "${MSF_HOST}" -p "${MSF_PORT}" -U msf -P "${MSF_PASSWORD}" -S true -f \
  >/tmp/msfrpcd.log 2>&1 &

# give msfrpcd a moment to bind
for i in $(seq 1 20); do
  if (echo > /dev/tcp/127.0.0.1/"${MSF_PORT}") 2>/dev/null; then
    echo "[h4k] msfrpcd is up."
    break
  fi
  sleep 1
done

echo "[h4k] starting API on 0.0.0.0:${API_PORT}..."
exec python3 -m uvicorn api.main:app --host 0.0.0.0 --port "${API_PORT}"
