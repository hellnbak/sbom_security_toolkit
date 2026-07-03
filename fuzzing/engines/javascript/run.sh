#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run.sh — drive Jazzer.js across every target with a per-target time budget.
#
#   TIME_BUDGET   seconds per target (default 300)
#   FINDINGS      output directory (default /fuzz/findings)
#   arg $1        optional single target name to run alone
# ---------------------------------------------------------------------------
set -uo pipefail

TIME_BUDGET="${TIME_BUDGET:-300}"
FINDINGS="${FINDINGS:-/fuzz/findings}"
TARGET_FILTER="${1:-}"

mkdir -p "$FINDINGS"
status=0

for target in /fuzz/targets/*.js /fuzz/targets/*.ts; do
    [ -f "$target" ] || continue

    name="$(basename "$target" .js)"
    name="$(basename "$name" .ts)"

    if [ -n "$TARGET_FILTER" ] && [ "$name" != "$TARGET_FILTER" ]; then
        continue
    fi

    crashdir="$FINDINGS/$name"
    corpus="$crashdir/corpus"
    mkdir -p "$corpus"

    # Seed the persistent corpus from bundled seeds
    if [ -d "/fuzz/corpus/$name" ]; then
        cp -n "/fuzz/corpus/$name/"* "$corpus/" 2>/dev/null || true
    fi

    echo "=================================================================="
    echo "[*] Fuzzing '$name' for ${TIME_BUDGET}s"
    echo "    corpus:    $corpus"
    echo "    crash dir: $crashdir"
    echo "=================================================================="

    # Jazzer.js writes crashes as crash-<hash> files in the corpus directory
    # We'll run with timeout to enforce the budget
    export JAZZER_FUZZ_TARGET="$target"

    ( cd "$crashdir" && timeout --preserve-status "${TIME_BUDGET}s" \
        npx jazzer "$target" "$corpus" 2>&1 | tee fuzz.log )
    rc=$?

    # Jazzer.js writes crashes to the corpus with 'crash-' prefix
    if ls "$corpus"/crash-* >/dev/null 2>&1; then
        echo "[!] CRASH(es) found for '$name':"
        ls -1 "$corpus"/crash-*
        # Move crashes to crash dir root for consistency with other engines
        mv "$corpus"/crash-* "$crashdir/"
        status=1
        python3 /fuzz/tools/record-crashes.py --engine javascript --target "$name" --target-file "$target" --crash-dir "$crashdir" || true
    else
        echo "[✓] '$name' finished its budget with no new crashes (rc=$rc)."
    fi
    echo
done

if [ "$status" -ne 0 ]; then
    cat <<'EOF'
------------------------------------------------------------------
[!] Crashes were found. Triage each one:

  # 1. Replay a crash to see the stack trace:
  docker run --rm -v "$PWD/findings:/fuzz/findings" \
    --entrypoint npx sbom-fuzzer-js \
    jazzer --reproduce=findings/<name>/crash-XXXX targets/<name>.js

  # 2. Run with coverage to understand code paths:
  docker run --rm -v "$PWD/findings:/fuzz/findings" \
    --entrypoint npx sbom-fuzzer-js \
    nyc jazzer targets/<name>.js findings/<name>/corpus

A thrown exception or unhandled rejection is a real bug. Whether it's
exploitable depends on whether the input is attacker-reachable.
------------------------------------------------------------------
EOF
fi

exit "$status"
