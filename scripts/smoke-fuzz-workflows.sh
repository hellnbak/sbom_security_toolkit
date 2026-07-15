#!/usr/bin/env bash
set -euo pipefail
SBOM="${SBOM:-test-sboms/clean/minimal-cyclonedx.json}"
XML_SBOM="${XML_SBOM:-vuln-scan/cyclonedx-sbom.xml}"
COUNT="${COUNT:-2}"
TIME_BUDGET="${TIME_BUDGET:-5}"
SMOKE_STEP_TIMEOUT="${SMOKE_STEP_TIMEOUT:-90}"

echo "[smoke] SBOM fuzz workflow smoke test"
echo "[smoke] JSON seed: $SBOM"
echo "[smoke] XML seed:  $XML_SBOM"

run() {
  echo
  echo "=== $* ==="
  if command -v timeout >/dev/null 2>&1; then
    timeout "$SMOKE_STEP_TIMEOUT" "$@"
  else
    "$@"
  fi
}

# Format-sensitive semantic workflows against JSON and CycloneDX XML.
for seed in "$SBOM" "$XML_SBOM"; do
  run python3 fuzzing/mutators/sbom_json_mutator.py "$seed" --out reports/fuzzing/smoke/structured --count "$COUNT"
  run python3 fuzzing/roundtrip/roundtrip_sbom.py "$seed" --out-dir reports/fuzzing/smoke/roundtrip
  run python3 fuzzing/metamorphic/metamorphic_sbom.py "$seed" --out-dir reports/fuzzing/smoke/metamorphic
  run python3 fuzzing/oracles/semantic_oracles.py "$seed" --out reports/fuzzing/smoke/semantic-oracles.json
  run python3 fuzzing/toolchain/fuzz_toolchain.py "$seed" --out reports/fuzzing/smoke/toolchain.json
  run python3 fuzzing/stateful/dependency_track_state_machine.py --url http://127.0.0.1:8081 --sbom "$seed" --dry-run --out reports/fuzzing/smoke/dtrack-stateful.json
  run python3 fuzzing/scanner-metamorphic/metamorphic_scanners.py "$seed" --out-dir reports/fuzzing/smoke/scanner-metamorphic
  run python3 fuzzing/conversion/convert_sbom.py "$seed" --format cyclonedx-json --out reports/fuzzing/smoke/converted.json
done

# Generator and operational workflows.
run python3 fuzzing/schema/cyclonedx_schema_generator.py --count "$COUNT" --edge valid-edge --out reports/fuzzing/smoke/generated-cyclonedx
run python3 fuzzing/schema/spdx_schema_generator.py --count "$COUNT" --edge valid-edge --out reports/fuzzing/smoke/generated-spdx
run python3 fuzzing/schema/vex_schema_generator.py --count "$COUNT" --out reports/fuzzing/smoke/generated-vex
run python3 fuzzing/schema/dependency_track_payload_generator.py "$XML_SBOM" --count "$COUNT" --out reports/fuzzing/smoke/dtrack-payloads
run python3 fuzzing/budgets/run_budget.py fuzzing/budgets/pr-smoke.yml --out reports/fuzzing/smoke/budget.json
run python3 fuzzing/status_report.py --out reports/fuzzing/smoke/status.md
echo "[smoke] benchmark mode is tested separately by make fuzz-benchmark; skipping inside smoke script to avoid nested long-running checks."
run python3 fuzzing/compatibility/scanner_compatibility.py --out reports/fuzzing/smoke/scanner-compatibility.json
run python3 fuzzing/truthset/scanner_truthset.py --out reports/fuzzing/smoke/truthset.json
run python3 fuzzing/intelligence/intelligence_score.py --out-dir reports/fuzzing/smoke/intelligence
echo "[smoke] corpus recommendation is tested separately by make fuzz-corpus-recommend."
run python3 fuzzing/harness/audit.py fuzzing/engines/python/targets/cyclonedx_json_atheris.py --out reports/fuzzing/smoke/harness-audit.json
run python3 fuzzing/grammar/run_grammar_mutator.py --grammar cyclonedx --count "$COUNT" --out reports/fuzzing/smoke/grammar
run python3 fuzzing/semantic_format_diff/semantic_format_diff.py "$SBOM" "$SBOM" --out reports/fuzzing/smoke/semantic-format-diff.json
run python3 fuzzing/vuln_matching/vuln_matching_fuzz.py --out-dir reports/fuzzing/smoke/vuln-matching
run python3 fuzzing/vex_logic/vex_logic_fuzz.py --out-dir reports/fuzzing/smoke/vex-logic
run python3 fuzzing/evil_supplier/evil_supplier.py --out-dir reports/fuzzing/smoke/evil-supplier
run python3 -m ai_fuzz.tools.ai_eval --providers none --out reports/fuzzing/smoke/ai-provider-eval.json
run python3 -m ai_fuzz.tools.ai_redteam --provider none --out reports/fuzzing/smoke/ai-redteam.json
run python3 fuzzing/clusterfuzzlite/import_results.py --out reports/fuzzing/smoke/cflite-results.json
run python3 fuzzing/clusterfuzzlite/ci_dashboard.py --results reports/fuzzing/smoke/cflite-results.json --out reports/fuzzing/smoke/ci-dashboard.html
run python3 fuzzing/findings_lifecycle/lifecycle.py --finding smoke --state triaged --notes smoke-test
run python3 fuzzing/visualize/fuzzing_lab_dashboard.py --out reports/fuzzing/smoke/lab-dashboard.html

echo
if command -v docker >/dev/null 2>&1; then
  echo "[smoke] Docker detected; containerized language engine fuzzing can run with make fuzz-python/fuzz-js/fuzz-php."
else
  echo "[smoke] Docker not detected; containerized language engine fuzzing was intentionally skipped."
fi

echo "[smoke] all fuzz workflow smoke checks completed"
