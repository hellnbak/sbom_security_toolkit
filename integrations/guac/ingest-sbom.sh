#!/usr/bin/env bash
set -euo pipefail
SBOM="${1:-test-sboms/clean/minimal-cyclonedx.json}"
echo "GUAC demo scaffold"
echo "SBOM: $SBOM"
echo "Install/run GUAC ingestion tooling for production graph ingestion."
echo "This script intentionally does not start network services by default."
