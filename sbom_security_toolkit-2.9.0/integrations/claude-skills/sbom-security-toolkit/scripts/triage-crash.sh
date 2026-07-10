#!/usr/bin/env bash
set -euo pipefail
CRASH="${1:?Usage: triage-crash.sh <crash-path>}"
make ai-crash-triage CRASH="$CRASH"
make fuzz-advisory CRASH="$CRASH"
