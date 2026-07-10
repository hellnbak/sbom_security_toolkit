#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# test-multi-ecosystem.sh — Smoke test for multi-ecosystem fuzzing setup
#
# Tests that each engine can build and run without errors.
# Does NOT run a full fuzzing campaign (use --budget 60 for quick test).
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILURES=0

echo "=================================================================="
echo " Multi-Ecosystem Fuzzing — Smoke Test"
echo "=================================================================="

# --- Test 1: Ecosystem detection --------------------------------------------
echo
echo "[Test 1/4] Ecosystem detection from SBOM..."
TEMP_COMPONENTS="/tmp/test-components-$$.json"
if python3 "$HERE/extract-components.py" "$HERE/vuln-scan/cyclonedx-sbom.xml" 2>/dev/null > "$TEMP_COMPONENTS"; then
    if ECOSYSTEMS=$(python3 "$HERE/fuzzing/detect-ecosystems.py" "$TEMP_COMPONENTS" 2>&1); then
        echo "  ✓ PASS: Found ecosystems:"
        echo "$ECOSYSTEMS" | sed 's/^/    /'
    else
        echo "  ✗ FAIL: detect-ecosystems.py crashed"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "  ✗ FAIL: extract-components.py crashed"
    FAILURES=$((FAILURES + 1))
fi
rm -f "$TEMP_COMPONENTS"

# --- Test 2: PHP engine -----------------------------------------------------
echo
echo "[Test 2/4] PHP engine build test..."
if docker build -q -t sbom-fuzzer-php "$HERE/fuzzing/engines/php" >/dev/null 2>&1; then
    echo "  ✓ PASS: PHP engine builds"
else
    echo "  ✗ FAIL: PHP engine build failed"
    FAILURES=$((FAILURES + 1))
fi

# --- Test 3: JavaScript engine ----------------------------------------------
echo
echo "[Test 3/4] JavaScript engine build test..."
if docker build -q -t sbom-fuzzer-javascript "$HERE/fuzzing/engines/javascript" >/dev/null 2>&1; then
    echo "  ✓ PASS: JavaScript engine builds"
else
    echo "  ✗ FAIL: JavaScript engine build failed"
    FAILURES=$((FAILURES + 1))
fi

# --- Test 4: Python engine --------------------------------------------------
echo
echo "[Test 4/4] Python engine build test..."
if docker build -q -t sbom-fuzzer-python "$HERE/fuzzing/engines/python" >/dev/null 2>&1; then
    echo "  ✓ PASS: Python engine builds"
else
    echo "  ✗ FAIL: Python engine build failed"
    FAILURES=$((FAILURES + 1))
fi

# --- Summary ----------------------------------------------------------------
echo
echo "=================================================================="
if [ "$FAILURES" -eq 0 ]; then
    echo "✓ All tests passed!"
    echo
    echo "Next steps:"
    echo "  1. Run a quick test: ./orchestrate.sh vuln-scan/cyclonedx-sbom.xml --budget 60 --skip-new-targets"
    echo "  2. Or full pipeline: ./orchestrate.sh vuln-scan/cyclonedx-sbom.xml"
    echo
    echo "See MULTI-ECOSYSTEM-FUZZING.md for documentation."
else
    echo "✗ $FAILURES test(s) failed"
    echo
    echo "Check Docker is installed and you have permission to run it."
    echo "Try: sudo usermod -aG docker $USER && newgrp docker"
fi
echo "=================================================================="

exit "$FAILURES"
