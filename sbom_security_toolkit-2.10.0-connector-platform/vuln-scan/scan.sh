#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# scan.sh — known-vulnerability analysis of a CycloneDX SBOM.
#
# Runs two independent, open-source scanners against the SBOM and writes
# machine-readable + human-readable reports. Using two engines that draw on
# different advisory sources (OSV.dev vs. the Aqua/Trivy DB, which also pulls
# GitHub Security Advisories) materially cuts the false-negative rate.
#
#   OSV-Scanner : https://github.com/google/osv-scanner   (Apache-2.0)
#   Trivy       : https://github.com/aquasecurity/trivy   (Apache-2.0)
#
# Both consume CycloneDX natively, so no language toolchain is required.
# Internet access IS required (advisory DBs are downloaded on first run).
# ---------------------------------------------------------------------------
set -euo pipefail

SBOM="${1:-cyclonedx-sbom.xml}"
OUTDIR="${2:-reports/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"

echo "[*] SBOM:    $SBOM"
echo "[*] Reports: $OUTDIR"

# Single shared scratch dir + trap for the whole script. Two separate
# `trap ... EXIT` calls would silently overwrite each other (bash traps on a
# given signal don't stack — the second replaces the first entirely), which
# would leak whichever one got set first. One trap, set once, avoids that.
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- OSV-Scanner -----------------------------------------------------------
# Pulls advisories from osv.dev (includes the PHP Security Advisories DB,
# GHSA, and CVE feeds). --format table for humans, SARIF + JSON for tooling.
#
# Two things changed under us since this was first written, confirmed against
# the current docs rather than guessed (google.github.io/osv-scanner/usage/
# scan-source#sbom-scanning), after --sbom started rejecting a real SBOM here:
#   1. --sbom is deprecated in favor of -L (same flag now used for both
#      lockfiles and SBOMs).
#   2. SBOM recognition is now filename-pattern-based, not content-based:
#      only bom.json, *.cdx.json, bom.xml, *.cdx.xml are auto-detected.
#      A real-world SBOM handed to this script can be named anything, so
#      rather than require the caller to rename their file, copy it to a
#      correctly-patterned temp name before invoking the scanner.
if command -v osv-scanner >/dev/null 2>&1; then
  echo "[*] Running OSV-Scanner..."
  case "$SBOM" in
    *.json) OSV_SBOM="$SCRATCH/osv-input.cdx.json" ;;
    *)      OSV_SBOM="$SCRATCH/osv-input.cdx.xml"  ;;
  esac
  cp "$SBOM" "$OSV_SBOM"

  osv-scanner scan source -L "$OSV_SBOM" --format table  | tee "$OUTDIR/osv.txt"  || true
  osv-scanner scan source -L "$OSV_SBOM" --format json  > "$OUTDIR/osv.json"      || true
  osv-scanner scan source -L "$OSV_SBOM" --format sarif > "$OUTDIR/osv.sarif"     || true
else
  echo "[!] osv-scanner not found. Install: https://github.com/google/osv-scanner#installation"
fi

# --- Trivy -----------------------------------------------------------------
# Independent advisory DB; --severity filter keeps the report actionable.
#
# Trivy has never supported CycloneDX XML as input — confirmed against
# Trivy's own current docs (trivy.dev/docs/latest/target/sbom: "CycloneDX XML
# is not supported at the moment"), not a version-specific regression like
# the OSV-Scanner change above. For XML input, build a minimal-but-valid
# CycloneDX JSON equivalent from the same component list extract-components.py
# already produces (name/version/purl per component) — enough for Trivy's
# purl-based vulnerability matching, though it won't carry every field a full
# spec-compliant XML->JSON conversion would (dependency graph, licenses, etc).
if command -v trivy >/dev/null 2>&1; then
  echo "[*] Running Trivy..."
  case "$SBOM" in
    *.json) TRIVY_SBOM="$SBOM" ;;
    *)
      TRIVY_SBOM="$SCRATCH/trivy-sbom.cdx.json"
      python3 "$SCRIPT_DIR/../extract-components.py" "$SBOM" 2>/dev/null | python3 -c '
import json, sys
components = json.load(sys.stdin)
bom = {
    "bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1,
    "components": [
        {"type": "library", "name": c["name"], "version": c.get("version") or "0.0.0", "purl": c["purl"]}
        for c in components if c.get("purl")
    ]
}
json.dump(bom, sys.stdout)
' > "$TRIVY_SBOM"
      echo "[*] (Trivy has no CycloneDX-XML support — converted to a minimal JSON equivalent for it: $(python3 -c "import json; print(len(json.load(open('$TRIVY_SBOM'))['components']))") components carried over)"
      ;;
  esac

  trivy sbom "$TRIVY_SBOM" --severity LOW,MEDIUM,HIGH,CRITICAL \
        --format table | tee "$OUTDIR/trivy.txt" || true
  trivy sbom "$TRIVY_SBOM" --format cyclonedx \
        --output "$OUTDIR/trivy-vex.cdx.json" || true
  trivy sbom "$TRIVY_SBOM" --format json \
        --output "$OUTDIR/trivy.json" || true
else
  echo "[!] trivy not found. Install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
fi

echo
echo "[✓] Done. Review:"
echo "    $OUTDIR/osv.txt"
echo "    $OUTDIR/trivy.txt"
echo
echo "    Feed osv.sarif into GitHub code scanning, or trivy-vex.cdx.json"
echo "    into a VEX workflow / Dependency-Track for tracking over time."
