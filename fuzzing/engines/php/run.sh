#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run.sh — drive php-fuzzer across every target with a per-target time budget.
#
#   TIME_BUDGET   seconds per target (default 300). For a real campaign use
#                 hours, e.g. TIME_BUDGET=14400.
#   arg $1        optional single target name (e.g. `commonmark`) to run alone.
#
# Persistent corpus + crash artifacts land in /fuzz/findings (bind-mount it so
# they survive the container and so corpora grow across runs).
# ---------------------------------------------------------------------------
set -uo pipefail

TIME_BUDGET="${TIME_BUDGET:-300}"
FINDINGS="${FINDINGS:-/fuzz/findings}"
TARGET_FILTER="${1:-}"

mkdir -p "$FINDINGS"
status=0

for target in /fuzz/targets/*.php; do
    name="$(basename "$target" .php)"
    if [ -n "$TARGET_FILTER" ] && [ "$name" != "$TARGET_FILTER" ]; then
        continue
    fi

    crashdir="$FINDINGS/$name"
    corpus="$crashdir/corpus"
    mkdir -p "$corpus"

    # Seed the persistent corpus from bundled seeds (only fills gaps; -n = no-clobber).
    if [ -d "/fuzz/corpus/$name" ]; then
        cp -n "/fuzz/corpus/$name/"* "$corpus/" 2>/dev/null || true
    fi

    echo "=================================================================="
    echo "[*] Fuzzing '$name' for ${TIME_BUDGET}s"
    echo "    corpus:    $corpus"
    echo "    crash dir: $crashdir"
    echo "=================================================================="

    # php-fuzzer runs until a crash or interrupt; `timeout` bounds the budget.
    # Crash files (crash-*.txt) are written to CWD, so run from the crash dir.
    ( cd "$crashdir" && timeout --preserve-status "${TIME_BUDGET}s" \
        php-fuzzer fuzz "$target" "$corpus" )
    rc=$?

    if ls "$crashdir"/crash-*.txt >/dev/null 2>&1; then
        echo "[!] CRASH(es) found for '$name':"
        ls -1 "$crashdir"/crash-*.txt
        status=1
        python3 /fuzz/tools/record-crashes.py --engine php --target "$name" --target-file "$target" --crash-dir "$crashdir" || true
    else
        echo "[✓] '$name' finished its budget with no new crashes (rc=$rc)."
    fi
    echo
done

if [ "$status" -ne 0 ]; then
    cat <<'EOF'
------------------------------------------------------------------
[!] Crashes were found. Triage each one — NOTE: php-fuzzer only exists
    inside this image, so run these from your HOST with --entrypoint,
    not directly (they will not be on your host PATH):

  # 1. Shrink the crashing input to its minimal form:
  docker run --rm -v "$PWD/findings:/fuzz/findings" --entrypoint php-fuzzer \
    sbom-fuzzer minimize-crash targets/<name>.php findings/<name>/crash-XXXX.txt

  # 2. Replay the minimized input to read the stack trace:
  docker run --rm -v "$PWD/findings:/fuzz/findings" --entrypoint php-fuzzer \
    sbom-fuzzer run-single targets/<name>.php findings/<name>/minimized-XXXX.txt

  # 3. Generate an HTML coverage report (written under findings/ so it lands
  #    back on your host):
  docker run --rm -v "$PWD/findings:/fuzz/findings" --entrypoint php-fuzzer \
    sbom-fuzzer report-coverage targets/<name>.php findings/<name>/corpus findings/<name>/coverage/

Remember: an uncaught \Error or a hang is a genuine bug. Whether it is a
*security* bug depends on whether the input is attacker-reachable in the app.
------------------------------------------------------------------
EOF
fi

exit "$status"
