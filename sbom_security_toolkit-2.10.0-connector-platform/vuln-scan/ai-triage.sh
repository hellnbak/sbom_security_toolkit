#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ai-triage.sh — turn raw OSV-Scanner / Trivy JSON into a prioritized,
# plain-English triage note, using the Claude API.
#
# WHAT THIS DOES vs. WHAT IT DOESN'T:
# scan.sh's raw output is complete but not prioritized — across 91 components
# that's a lot of JSON to read by hand (it's exactly what took several
# rounds of manual digging to turn into triage-2026-06.md earlier). This
# script automates that FIRST pass: read every finding, explain the actual
# risk in plain English, surface any gating condition the advisory mentions
# (e.g. "only if extension X is enabled" — the kind of detail that changes
# whether something is P0 or a non-issue), and sort by what to look at first.
#
# It does NOT read your application source, so it cannot tell you whether a
# finding is actually reachable in your codebase — only a human, or the
# Claude Code workflow documented in the README's "AI-assisted analysis"
# section (which DOES have repo access), can answer that. Treat this
# script's output as a sorted first draft, not a verdict.
#
# Requires: jq, python3, and the `anthropic` package — see call_claude.py's
# docstring for the exact install command (it depends on your pip version).
#
# Usage:
#   export ANTHROPIC_API_KEY="your_anthropic_api_key_here"
#   ./ai-triage.sh reports/<timestamp>/osv.json reports/<timestamp>/trivy.json
#
# On the EC2/Bedrock deployment (see ../aws/), instead set:
#   export CLAUDE_BACKEND=bedrock
#   export AWS_REGION=us-east-1        # wherever your model access is granted
# No ANTHROPIC_API_KEY needed there — auth comes from the instance's IAM role.
# ---------------------------------------------------------------------------
set -euo pipefail

CLAUDE_BACKEND="${CLAUDE_BACKEND:-direct}"
if [ "$CLAUDE_BACKEND" = "direct" ]; then
  : "${ANTHROPIC_API_KEY:?Set ANTHROPIC_API_KEY, or export CLAUDE_BACKEND=bedrock on the EC2 deployment.}"
fi
command -v jq      >/dev/null 2>&1 || { echo "[!] jq is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[!] python3 is required"; exit 1; }

OSV_JSON="${1:?Usage: $0 <osv.json> [trivy.json] [output.md]}"
TRIVY_JSON="${2:-}"
OUT="${3:-ai-triage-$(date +%Y%m%d-%H%M%S).md}"

[ -f "$OSV_JSON" ] || { echo "[!] Not found: $OSV_JSON"; exit 1; }
jq -e . "$OSV_JSON" >/dev/null 2>&1 || { echo "[!] Not valid JSON: $OSV_JSON"; exit 1; }

# Deliberately NOT pre-parsing specific fields out of the scanner JSON here.
# OSV-Scanner and Trivy's exact schemas shift between versions, and getting
# a jq field path subtly wrong would silently hand Claude an empty array
# instead of erroring — worse than just passing the real JSON through and
# letting it parse whatever shape actually came out of your installed
# scanner version. A size cap keeps this sane on very large scans.
MAX_BYTES=300000
OSV_CONTENT=$(head -c "$MAX_BYTES" "$OSV_JSON")
if [ -n "$TRIVY_JSON" ] && [ -f "$TRIVY_JSON" ]; then
  TRIVY_CONTENT=$(head -c "$MAX_BYTES" "$TRIVY_JSON")
else
  TRIVY_CONTENT="(not provided)"
fi

echo "[*] Sending findings to Claude for triage..."

SYSTEM_PROMPT='You are triaging open-source dependency vulnerability scan output for a PHP/Laravel application. You will be given raw JSON from two independent scanners (OSV-Scanner and Trivy) run against the same CycloneDX SBOM — their exact schemas may vary by version, so parse whatever structure is actually present.

For each DISTINCT vulnerability (dedupe when both scanners report the same CVE/GHSA/advisory for the same package), produce:
1. Package + version affected, and the advisory ID(s).
2. A one-sentence plain-English summary of the actual risk — not a restated CVSS vector string.
3. Any gating condition the advisory itself mentions (e.g. "only if X extension/config is enabled", "only affects raw serialization, not the normal client path"). If the advisory does NOT mention a gating condition, say so explicitly — that means broader exposure by default, which is itself important information.
4. A priority: P0 (patch immediately — reachable-by-default and high impact), P1 (patch this sprint), P2 (patch on the normal cycle), or P3 (low urgency, likely low real-world impact, or needs verification it even applies).
5. One concrete thing a human should go check in the actual codebase to confirm real exposure — a function name, a config flag, a usage pattern to grep for.

Output as a Markdown document, sorted P0 first. Be concise and concrete — this is a working triage draft a security engineer will read once and act on, not a formal report. Do not hedge everything; if a finding is clearly low-risk given its gating condition, say that plainly. If the input JSON has zero findings, say that plainly and stop.'

USER_PROMPT=$(cat <<PROMPT_EOF
OSV-Scanner JSON output:
${OSV_CONTENT}

Trivy JSON output:
${TRIVY_CONTENT}
PROMPT_EOF
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
printf '%s' "$SYSTEM_PROMPT" > "$TMPDIR/system.txt"
printf '%s' "$USER_PROMPT"   > "$TMPDIR/prompt.txt"

REPORT=$(python3 "$SCRIPT_DIR/call_claude.py" \
  --backend "$CLAUDE_BACKEND" \
  --system-file "$TMPDIR/system.txt" \
  --prompt-file "$TMPDIR/prompt.txt" \
  --max-tokens 8192) || { echo "[!] Claude call failed — see error above."; exit 1; }

{
  echo "# AI-Assisted Triage — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "> Generated from scanner JSON, without codebase access, via the"
  echo "> ${CLAUDE_BACKEND} backend. Confirm P0/P1 items against the actual"
  echo "> advisory links and your application source before acting — see"
  echo "> the README's Claude Code reachability workflow for a repo-aware"
  echo "> follow-up pass."
  echo
  echo "$REPORT"
} > "$OUT"

echo "[✓] Wrote $OUT"
