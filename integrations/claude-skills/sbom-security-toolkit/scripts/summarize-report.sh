#!/usr/bin/env bash
set -euo pipefail
REPORT_DIR="${1:-reports/latest}"
find "$REPORT_DIR" -maxdepth 2 -type f \( -name '*.md' -o -name '*.json' -o -name '*.csv' \) | sort
