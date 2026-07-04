#!/usr/bin/env bash
set -euo pipefail
VERSION="${VERSION:-${1:-}}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: VERSION=1.8.0 scripts/release.sh" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[release] running tests"
make test

echo "[release] validating"
make validate

echo "[release] cleaning generated artifacts before preflight"
rm -rf reports release-evidence fuzzing/findings fuzzing/reports fuzzing/generated-corpus fuzzing/crashes test-sboms/evil-supplier fuzzing/findings_lifecycle/findings.json ai_fuzz/review/incoming/harness-quality-loop ai_fuzz/review/incoming/generators ui/storage/jobs ui/storage/uploads
find . -type d -name __pycache__ -prune -exec rm -rf {} +
find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
mkdir -p ui/storage/jobs ui/storage/uploads
touch ui/storage/jobs/.gitkeep ui/storage/uploads/.gitkeep

echo "[release] preflight"
make preflight-release

OUT="dist/sbom-security-toolkit-fsl-v${VERSION}.zip"
rm -rf dist
mkdir -p dist
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
rsync -a --exclude='.git' --exclude='.venv' --exclude='dist' --exclude='reports' --exclude='release-evidence' --exclude='ui/storage/jobs/*' --exclude='ui/storage/uploads/*' ./ "$TMP/sbom-security-toolkit/"
(cd "$TMP/sbom-security-toolkit" && find . -type d -name __pycache__ -prune -exec rm -rf {} + && find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete)
(cd "$TMP/sbom-security-toolkit" && zip -qr "$ROOT/$OUT" .)
(cd dist && shasum -a 256 "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "[release] wrote $OUT"
