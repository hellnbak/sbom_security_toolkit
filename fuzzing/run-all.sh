#!/usr/bin/env bash
set -euo pipefail

MODE="smoke"
FINDINGS="$(pwd)/fuzzing/findings"
ENGINES="python javascript php"
TIME_BUDGET="${TIME_BUDGET:-60}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --findings) FINDINGS="$2"; shift 2 ;;
    --engines) ENGINES="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  smoke) : "${TIME_BUDGET:=60}" ;;
  nightly) : "${TIME_BUDGET:=1800}" ;;
  deep) : "${TIME_BUDGET:=14400}" ;;
  *) echo "Unknown mode: $MODE" >&2; exit 2 ;;
esac

mkdir -p "$FINDINGS" fuzzing/reports
status=0
if ! command -v docker >/dev/null 2>&1; then
  echo "[skip] Docker not installed; skipping containerized language-engine fuzzing."
  python3 fuzzing/tools/scorecard.py "$FINDINGS" --output fuzzing/reports/fuzz-scorecard.md || true
  exit 0
fi
for engine in $ENGINES; do
  dir="fuzzing/engines/$engine"
  [ -d "$dir" ] || { echo "[skip] no engine: $engine"; continue; }
  image="sbom-fuzzer-$engine"
  [ "$engine" = "javascript" ] && image="sbom-fuzzer-javascript"
  echo "[*] Building $image"
  docker build -t "$image" "$dir"
  echo "[*] Running $engine fuzzing mode=$MODE budget=${TIME_BUDGET}s findings=$FINDINGS"
  docker run --rm -e TIME_BUDGET="$TIME_BUDGET" -v "$FINDINGS:/fuzz/findings" "$image" || status=$?
done

python3 fuzzing/tools/scorecard.py "$FINDINGS" --output fuzzing/reports/fuzz-scorecard.md || true
exit "$status"
