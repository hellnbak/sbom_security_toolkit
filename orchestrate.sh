#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# orchestrate.sh — feed this any CycloneDX SBOM; it runs the pipeline.
#
#   ./orchestrate.sh path/to/any-cyclonedx-sbom.xml
#
# WHAT'S ACTUALLY GENERIC vs. WHAT ISN'T (read this before trusting output):
#
#   Vulnerability scanning (Stage 1) is ecosystem-agnostic already — OSV-
#   Scanner and Trivy both do multi-ecosystem CVE lookups, so an npm or
#   Python or Java CycloneDX SBOM works here completely unmodified.
#
#   Fuzzing (Stage 3+) is NOT ecosystem-agnostic and can't be made so without
#   separate engines per language (this toolkit only wires up PHP-Fuzzer for
#   PHP/Composer). If the SBOM contains other ecosystems, this script scans
#   them for known CVEs same as anything else, then says so plainly and
#   stops there for those components — it does not pretend to fuzz what it
#   has no engine for.
#
# WHAT "TAKES OVER" MEANS HERE, CONCRETELY:
#   - Stage 1 (scan) and Stage 2 (AI triage) run fully unattended.
#   - Stage 3 (target selection + harness generation) hands the PHP/Composer
#     component list to Claude Code and lets IT decide what's worth fuzzing
#     and write the harnesses, rather than a human hand-picking targets.
#   - Stage 4 (fuzz) runs unattended for a bounded time budget.
#   - It does NOT mean nothing needs human review afterward. Generated
#     targets, triage severity calls, and any crash all still need a human
#     to look at them before anyone treats this as a verdict — that list is
#     printed at the end, not buried.
#
# Flags:
#   --auto              Unattended mode: skip Claude Code permission prompts
#                        (--dangerously-skip-permissions). Fine in CI, on a
#                        disposable runner, or a box you don't mind Claude
#                        having unattended write access to. Off by default.
#   --budget SECONDS     Fuzz time per target (default 300).
#   --skip-new-targets   Only fuzz targets that already exist; don't ask
#                        Claude Code to generate more.
#   --skip-fuzz          Stop after scan + triage + target generation.
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBOM="${1:?Usage: $0 <path-to-cyclonedx-sbom> [--auto] [--budget SECONDS] [--skip-new-targets] [--skip-fuzz]}"
shift || true

AUTO=0
BUDGET=300
SKIP_NEW_TARGETS=0
SKIP_FUZZ=0
while [ $# -gt 0 ]; do
  case "$1" in
    --auto) AUTO=1 ;;
    --budget) BUDGET="$2"; shift ;;
    --skip-new-targets) SKIP_NEW_TARGETS=1 ;;
    --skip-fuzz) SKIP_FUZZ=1 ;;
    *) echo "[!] Unknown flag: $1"; exit 1 ;;
  esac
  shift
done

[ -f "$SBOM" ] || { echo "[!] Not found: $SBOM"; exit 1; }
SBOM="$(cd "$(dirname "$SBOM")" && pwd)/$(basename "$SBOM")"   # absolute path

RUN_DIR="$HERE/runs/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"
echo "=================================================================="
echo " Orchestrating against: $SBOM"
echo " Run directory:         $RUN_DIR"
echo "=================================================================="

# --- Stage 1: vulnerability scan (already ecosystem-agnostic) --------------
echo; echo "[Stage 1/4] Vulnerability scan..."
( cd "$HERE/vuln-scan" && ./scan.sh "$SBOM" "$RUN_DIR/vuln-scan" )

# --- Stage 2: AI triage of the scan (Tier 1 — no repo access needed) -------
echo; echo "[Stage 2/4] AI triage..."
if [ -n "${ANTHROPIC_API_KEY:-}" ] || [ "${CLAUDE_BACKEND:-}" = "bedrock" ]; then
  ( cd "$HERE/vuln-scan" && ./ai-triage.sh \
      "$RUN_DIR/vuln-scan/osv.json" "$RUN_DIR/vuln-scan/trivy.json" \
      "$RUN_DIR/ai-triage.md" ) || echo "[!] Triage step failed — continuing without it."
else
  echo "  Skipped — set ANTHROPIC_API_KEY (direct) or CLAUDE_BACKEND=bedrock (EC2) to enable this step."
fi

# --- Extract components + tally ecosystems ----------------------------------
echo; echo "[*] Extracting components from SBOM..."
python3 "$HERE/extract-components.py" "$SBOM" > "$RUN_DIR/components.json" \
  || { echo "[!] Component extraction failed — see error above."; exit 1; }

ECOSYSTEMS=$(python3 - "$RUN_DIR/components.json" <<'PYEOF'
import json, re, sys
from collections import Counter
data = json.load(open(sys.argv[1]))
tally = Counter()
for c in data:
    m = re.match(r'pkg:([^/]+)/', c.get('purl') or '')
    tally[m.group(1) if m else 'no-purl'] += 1
for eco, n in sorted(tally.items(), key=lambda x: -x[1]):
    print(f"{eco}:{n}")
PYEOF
)
echo "  Ecosystems found:"
echo "$ECOSYSTEMS" | sed 's/^/    /'

# --- Detect which engines we have available for this SBOM ------------------
ECOSYSTEM_MAP=$(python3 "$HERE/fuzzing/detect-ecosystems.py" "$RUN_DIR/components.json")
echo "  Ecosystem → Engine mapping:"
echo "$ECOSYSTEM_MAP" | while read line; do
  ECO=$(echo "$line" | cut -d: -f1)
  COUNT=$(echo "$line" | cut -d: -f2)
  ENGINE=$(echo "$line" | cut -d: -f3)
  if [ "$ENGINE" = "none" ]; then
    echo "    $ECO ($COUNT components) → no engine (CVE scan only)"
  elif [ -d "$HERE/fuzzing/engines/$ENGINE" ]; then
    echo "    $ECO ($COUNT components) → engines/$ENGINE ✓"
  else
    echo "    $ECO ($COUNT components) → engines/$ENGINE (not installed)"
  fi
done

# --- Stage 3: let Claude Code pick + build new fuzz targets ----------------
if [ "$SKIP_NEW_TARGETS" -eq 1 ]; then
  echo; echo "[Stage 3/4] Skipped (--skip-new-targets)."
elif ! command -v claude >/dev/null 2>&1; then
  echo; echo "[Stage 3/4] Skipped — Claude Code not found on PATH."
  echo "  Install: npm install -g @anthropic-ai/claude-code"
  echo "  Without it, fuzzing (Stage 4) will only run the targets that already exist."
else
  echo; echo "[Stage 3/4] Claude Code: selecting + generating new fuzz targets..."
  PERM_FLAGS=""
  [ "$AUTO" -eq 1 ] && PERM_FLAGS="--dangerously-skip-permissions"

  # Run target generation for each ecosystem with an available engine
  echo "$ECOSYSTEM_MAP" | while read line; do
    ECO=$(echo "$line" | cut -d: -f1)
    COUNT=$(echo "$line" | cut -d: -f2)
    ENGINE=$(echo "$line" | cut -d: -f3)

    if [ "$ENGINE" = "none" ] || [ ! -d "$HERE/fuzzing/engines/$ENGINE" ]; then
      continue
    fi

    echo; echo "  [Stage 3.$ECO] Generating targets for $ECO ($COUNT components)..."
    EXISTING_TARGETS=$(ls "$HERE/fuzzing/engines/$ENGINE/targets" 2>/dev/null | sed -E 's/\.(php|js|ts|py|java|go|rs)$//' | tr '\n' ',' || true)

    ( cd "$HERE/fuzzing/engines/$ENGINE" && claude -p $PERM_FLAGS \
        --allowedTools "Read,Write,Bash" --max-turns 30 --output-format text \
        "You are extending a fuzzing harness for $ENGINE in this directory. Read 2-3 files under targets/ as examples of the established pattern. Existing targets already built: ${EXISTING_TARGETS}.

Here is the full component list from a freshly-scanned CycloneDX SBOM:
$(cat "$RUN_DIR/components.json")

For $ECO components (purl starting pkg:$ECO/) that are NOT already covered above, and that plausibly parse untrusted or external input — markdown, YAML, XML/JSON, URIs, email addresses, templates, file paths, numeric strings, HTTP messages, archives, images — as opposed to things that structurally can't be fuzzed usefully (loggers, DI containers, simple value objects, framework glue, CLI/dev tooling): pick at most 5, prioritizing by how directly attacker-reachable input is likely to flow into each. For each one picked: add it to the dependency manifest at its EXACT pinned version from the component list, write a target file following the existing pattern, and add 3-5 seed files under corpus/. Skip every non-$ECO purl entirely. When done, print a short list of what you added and a one-line reason for each, and nothing else." \
        2>&1 | tee "$RUN_DIR/claude-code-$ECO-targets.log" )
    echo "  Log: $RUN_DIR/claude-code-$ECO-targets.log"
  done
fi

# --- Stage 4: fuzz everything that exists now -------------------------------
if [ "$SKIP_FUZZ" -eq 1 ]; then
  echo; echo "[Stage 4/4] Skipped (--skip-fuzz)."
elif ! command -v docker >/dev/null 2>&1; then
  echo; echo "[Stage 4/4] Skipped — Docker not found."
else
  echo; echo "[Stage 4/4] Building fuzzing images and running (${BUDGET}s/target)..."

  # Run fuzzing for each ecosystem with an available engine
  echo "$ECOSYSTEM_MAP" | while read line; do
    ECO=$(echo "$line" | cut -d: -f1)
    ENGINE=$(echo "$line" | cut -d: -f3)

    if [ "$ENGINE" = "none" ] || [ ! -d "$HERE/fuzzing/engines/$ENGINE" ]; then
      continue
    fi

    echo; echo "  [Stage 4.$ECO] Fuzzing $ECO components with $ENGINE engine..."
    mkdir -p "$RUN_DIR/findings-$ECO"

    ( cd "$HERE/fuzzing/engines/$ENGINE" && docker build -q -t "sbom-fuzzer-$ENGINE" . )
    ( cd "$HERE/fuzzing/engines/$ENGINE" && docker run --rm \
        -e TIME_BUDGET="$BUDGET" \
        -v "$RUN_DIR/findings-$ECO:/fuzz/findings" \
        "sbom-fuzzer-$ENGINE" ) || true   # crashes exit non-zero; don't fail the pipeline
  done
fi

# --- Summary -----------------------------------------------------------------
SUMMARY="$RUN_DIR/SUMMARY.md"
{
  echo "# Orchestration Summary — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "SBOM: \`$SBOM\`"
  echo
  echo "## Ecosystems found"
  echo '```'
  echo "$ECOSYSTEMS"
  echo '```'
  echo
  if [ -f "$RUN_DIR/ai-triage.md" ]; then
    echo "## Vulnerability triage: see ai-triage.md in this directory"
  else
    echo "## Vulnerability scan: see vuln-scan/osv.txt and vuln-scan/trivy.txt in this directory"
  fi
  echo
  echo "## Fuzzing results"
  FOUND_FINDINGS=0
  for findings_dir in "$RUN_DIR"/findings-*/; do
    [ -d "$findings_dir" ] || continue
    FOUND_FINDINGS=1
    eco=$(basename "$findings_dir" | sed 's/findings-//')
    echo
    echo "### $eco"
    for d in "$findings_dir"*/; do
      [ -d "$d" ] || continue
      name=$(basename "$d")
      if ls "$d"crash-*.txt >/dev/null 2>&1; then
        echo "- **${name}: CRASH FOUND** — see findings-$eco/${name}/"
      else
        echo "- ${name}: no crash this run"
      fi
    done
  done
  if [ "$FOUND_FINDINGS" -eq 0 ]; then
    echo "(no fuzzing engines ran this run)"
  fi
  echo
  echo "## Still needs a human"
  echo "- Any component Claude Code added a target for — read the generated code before trusting it long-term (see claude-code-*-targets.log files)."
  echo "- Any P0/P1 item in the triage — a model synthesis, not a verdict; confirm reachability against actual code."
  echo "- Any crash found above — minimize/replay it (see fuzzing/engines/<engine>/run.sh for commands) and judge attacker-reachability yourself."
} > "$SUMMARY"

echo
echo "=================================================================="
echo "[✓] Done. Read: $SUMMARY"
echo "=================================================================="
