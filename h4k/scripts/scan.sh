#!/usr/bin/env bash
# Basic recon automation template (school lab use only).
# Usage: bash scan.sh TARGET_IP
set -euo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 TARGET_IP" >&2
  exit 1
fi

echo "[*] Port scan: $TARGET"
nmap -Pn -T4 -sV --top-ports 100 "$TARGET"
echo "[*] Scan complete."
