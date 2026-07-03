#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-checksums}"
ARTIFACT_DIR="${ARTIFACT_DIR:-dist}"
OUT_DIR="${OUT_DIR:-release-evidence/artifacts}"
mkdir -p "$OUT_DIR"
case "$MODE" in
  checksums)
    if [ ! -d "$ARTIFACT_DIR" ]; then echo "Artifact directory $ARTIFACT_DIR does not exist; creating empty manifest"; mkdir -p "$ARTIFACT_DIR"; fi
    find "$ARTIFACT_DIR" -type f -print0 | sort -z | xargs -0 shasum -a 256 > "$OUT_DIR/SHA256SUMS" || true
    echo "$OUT_DIR/SHA256SUMS"
    ;;
  sign)
    if command -v cosign >/dev/null 2>&1; then
      cosign sign-blob --yes "$OUT_DIR/SHA256SUMS" --output-signature "$OUT_DIR/SHA256SUMS.sig" --output-certificate "$OUT_DIR/SHA256SUMS.pem"
    else
      echo "cosign not installed; writing signing instructions" > "$OUT_DIR/SIGNING-NOTES.txt"
      echo "Install cosign and re-run: ARTIFACT_DIR=$ARTIFACT_DIR $0 sign" >> "$OUT_DIR/SIGNING-NOTES.txt"
    fi
    ;;
  verify)
    if command -v cosign >/dev/null 2>&1 && [ -f "$OUT_DIR/SHA256SUMS.sig" ]; then
      cosign verify-blob "$OUT_DIR/SHA256SUMS" --signature "$OUT_DIR/SHA256SUMS.sig" --certificate "$OUT_DIR/SHA256SUMS.pem"
    else
      echo "No cosign signature present. Verify checksums with: shasum -a 256 -c $OUT_DIR/SHA256SUMS"
    fi
    ;;
  *) echo "Usage: $0 checksums|sign|verify"; exit 2;;
esac
