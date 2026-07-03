#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-cyclonedx}"
IN="${IN:-fuzzing/generated-corpus/schema/$TARGET}"
OUT="${OUT:-fuzzing/findings/afl-$TARGET}"
mkdir -p "$OUT"
if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "AFL++ not installed. Install afl-fuzz or run this inside an AFL++ container." | tee "$OUT/README.txt"
  exit 0
fi
echo "AFL++ installed. Configure a harness binary via HARNESS=/path/to/harness."
: "${HARNESS:?Set HARNESS=/path/to/instrumented/harness}"
afl-fuzz -i "$IN" -o "$OUT" -- "$HARNESS" @@
