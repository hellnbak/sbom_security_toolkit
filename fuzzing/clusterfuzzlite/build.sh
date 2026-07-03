#!/usr/bin/env bash
set -euo pipefail

# Template build hook for ClusterFuzzLite-style environments.
# This project primarily uses Dockerized language fuzzers; adapt this script
# for a self-hosted runner or a project-specific build farm.

echo "Build the desired fuzzing image before running ClusterFuzzLite."
echo "Example: docker build -t sbom-fuzzer-python fuzzing/engines/python"
