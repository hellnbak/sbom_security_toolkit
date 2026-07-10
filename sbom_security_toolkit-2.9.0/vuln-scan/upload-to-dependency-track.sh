#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# upload-to-dependency-track.sh — push the SBOM into a running Dependency-
# Track instance via its REST API, so it starts continuously monitoring it.
#
# Usage:
#   export DTRACK_URL=http://localhost:8081
#   export DTRACK_API_KEY=odt_xxxxxxxxxxxxxxxxxxxx   # Teams -> (your team) -> API Keys
#   ./upload-to-dependency-track.sh cyclonedx-sbom.xml "Example Laravel Application" 1.0
#
# Re-run this after every SBOM regeneration (e.g. from CI) — autoCreate=true
# means the first call creates the project, later calls just add a new BOM
# version to it, which is what powers the "was this vulnerable last month"
# history in the UI.
# ---------------------------------------------------------------------------
set -euo pipefail

BOM_FILE="${1:?Usage: $0 <bom-file> <project-name> <project-version>}"
PROJECT_NAME="${2:?Usage: $0 <bom-file> <project-name> <project-version>}"
PROJECT_VERSION="${3:?Usage: $0 <bom-file> <project-name> <project-version>}"

: "${DTRACK_URL:?Set DTRACK_URL, e.g. export DTRACK_URL=http://localhost:8081}"
: "${DTRACK_API_KEY:?Set DTRACK_API_KEY from Administration -> Access Management -> Teams}"

echo "[*] Uploading $BOM_FILE to $DTRACK_URL as '$PROJECT_NAME' v$PROJECT_VERSION"

http_code=$(curl -sS -o /tmp/dtrack-response.json -w "%{http_code}" \
  -X POST "${DTRACK_URL}/api/v1/bom" \
  -H "X-Api-Key: ${DTRACK_API_KEY}" \
  -F "autoCreate=true" \
  -F "projectName=${PROJECT_NAME}" \
  -F "projectVersion=${PROJECT_VERSION}" \
  -F "bom=@${BOM_FILE}")

if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
  echo "[✓] Uploaded (HTTP $http_code). Dependency-Track is now analyzing it asynchronously."
  echo "    Check the project's Findings tab in a minute or two: ${DTRACK_URL%:8081}:8080"
else
  echo "[!] Upload failed (HTTP $http_code):"
  cat /tmp/dtrack-response.json
  exit 1
fi
