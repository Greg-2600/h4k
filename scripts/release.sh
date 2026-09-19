#!/usr/bin/env bash
# Build + tag the h4k platform image and print the one-line run command.
#
# Usage:
#   bash scripts/release.sh v1.1.0
#
# Tags: h4k:latest, h4k:<ver>, localhost:5000/h4k:<ver> (if REGISTRY set)
set -euo pipefail

VER="${1:-$(git describe --tags --always 2>/dev/null || echo v0.0.0)}"
VER="${VER#v}"           # strip leading v for the tag
REGISTRY="${REGISTRY:-}"

echo "==> Building h4k image (tag: ${VER})"
docker build -t "h4k:latest" -t "h4k:v${VER}" h4k/

if [[ -n "${REGISTRY}" ]]; then
  echo "==> Tagging + pushing to ${REGISTRY}"
  docker tag "h4k:v${VER}" "${REGISTRY}/h4k:v${VER}"
  docker tag "h4k:latest" "${REGISTRY}/h4k:latest"
  docker push "${REGISTRY}/h4k:v${VER}"
  docker push "${REGISTRY}/h4k:latest"
fi

echo
echo "==> h4k v${VER} ready."
echo
cat <<'EOF'
One-line run (host networking, requires a reachable Ollama for AI assist):

  docker run -d --name h4k --network host \
    -e API_PORT=3137 -e MSF_PASSWORD=h4k_msf_rocks \
    -e H4K_AI_PROVIDER=ollama -e OLLAMA_BASE_URL=http://127.0.0.1:11434 -e H4K_AI_MODEL=qwen2.5:latest \
    h4k:vVER
EOF
