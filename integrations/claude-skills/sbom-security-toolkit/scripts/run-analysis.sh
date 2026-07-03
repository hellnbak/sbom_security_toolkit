#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-.}"
OUT="${2:-reports/claude-skill-analysis}"
python3 -m sbomops.cli analyze "$TARGET" --out-dir "$OUT"
echo "Analysis written to $OUT"
