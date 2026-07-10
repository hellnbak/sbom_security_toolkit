#!/usr/bin/env bash
set -euo pipefail
python3 -m compileall -q .
mkdir -p "$OUT"
cat > "$OUT/sbom_smoke_fuzzer" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
python3 fuzzing/oracles/semantic_oracles.py "${1:-test-sboms/clean/minimal-cyclonedx.json}" --out /tmp/sbom-oracles.json >/dev/null
EOF
chmod +x "$OUT/sbom_smoke_fuzzer"
