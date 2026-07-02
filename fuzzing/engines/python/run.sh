#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run.sh — drive Atheris across every target with a per-target time budget.
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

for target in /fuzz/targets/*.py; do
    [ -f "$target" ] || continue

    name="$(basename "$target" .py)"

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

    # Atheris writes crashes as crash-<hash> files
    # Run with timeout to enforce budget
    ( cd "$crashdir" && timeout --preserve-status "${TIME_BUDGET}s" \
        python3 "$target" "$corpus" -max_total_time="${TIME_BUDGET}" 2>&1 | tee fuzz.log )
    rc=$?

    # Atheris writes crashes with 'crash-' prefix in the working directory
    if ls "$crashdir"/crash-* >/dev/null 2>&1; then
        echo "[!] CRASH(es) found for '$name':"
        ls -1 "$crashdir"/crash-*
        status=1
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
    --entrypoint python3 sbom-fuzzer-python \
    targets/<name>.py findings/<name>/crash-XXXX

  # 2. Minimize the crash input:
  docker run --rm -v "$PWD/findings:/fuzz/findings" \
    --entrypoint python3 sbom-fuzzer-python \
    targets/<name>.py findings/<name>/crash-XXXX -minimize_crash=1

An uncaught exception or assertion failure is a real bug. Whether it's
exploitable depends on whether the input is attacker-reachable.
------------------------------------------------------------------
EOF
fi

exit "$status"
