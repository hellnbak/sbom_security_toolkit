#!/usr/bin/env bash
set -euo pipefail
SBOM="${SBOM:-vuln-scan/cyclonedx-sbom.xml}"
POLICY="${POLICY:-policies/default-release-policy.yml}"
OUT="${OUT:-release-evidence}"
mkdir -p "$OUT"
python3 -m sbomops.score_sbom "$SBOM" --out-dir "$OUT/sbom-quality"
python3 -m sbomops.policy_check "$SBOM" --policy "$POLICY" --out-dir "$OUT/policy"
python3 -m sbomops.supplier_intake "$SBOM" --out-dir "$OUT/supplier-intake"
python3 -m sbomops.scanner_compare "$SBOM" --out-dir "$OUT/scanner-compare"
python3 -m sbomops.report "$SBOM" --out-dir "$OUT/report-bundle"
python3 -m sbomops.ui --reports-dir "$OUT" --out "$OUT/index.html"
cp "$SBOM" "$OUT/" || true
printf 'Release evidence written to %s\n' "$OUT"
