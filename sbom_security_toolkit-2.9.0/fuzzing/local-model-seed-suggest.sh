#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# local-model-seed-suggest.sh — use a LOCAL model (via Ollama) to propose new
# seed inputs for one fuzz target, based on its source + current corpus.
#
# WHY A LOCAL MODEL FOR THIS SPECIFIC TASK: seed suggestion is a good fit for
# local/small models, unlike final vulnerability triage (see the README's
# "what the evidence says" section — open-weight models plateau hard on
# actual vuln-detection judgment calls). Seed generation is narrower, needs
# no security judgment, and benefits from being cheap enough to re-run every
# few minutes during a long campaign. This isn't speculative: SeedMind,
# LLAMAFUZZ, and ISC4DGF (all 2024-2026, cited in the README) specifically
# study LLM-assisted seed generation and show real coverage gains using
# models far smaller than frontier scale.
#
# This does NOT touch php-fuzzer's own mutation engine — it only adds
# candidate starting material to corpus/<target>/, the same role the
# hand-written seeds already play. A bad suggestion is inert: php-fuzzer's
# coverage-guided selection just never picks it up as "interesting."
#
# Requires: Ollama running locally (https://ollama.com) with a pulled model.
#   ollama pull qwen2.5-coder:7b     (or any code-capable model you have)
#
# Usage:
#   ./local-model-seed-suggest.sh <target-name> [count] [ollama-model]
#   ./local-model-seed-suggest.sh commonmark 10
# ---------------------------------------------------------------------------
set -euo pipefail

TARGET="${1:?Usage: $0 <target-name> [count] [ollama-model]}"
COUNT="${2:-10}"
MODEL="${3:-qwen2.5-coder:7b}"

TARGET_FILE="targets/${TARGET}.php"
CORPUS_DIR="corpus/${TARGET}"

[ -f "$TARGET_FILE" ] || { echo "[!] No such target: $TARGET_FILE (run this from fuzzing/)"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[!] curl is required"; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "[!] jq is required"; exit 1; }
mkdir -p "$CORPUS_DIR"

curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 || {
  echo "[!] Ollama isn't responding on localhost:11434."
  echo "    Install: https://ollama.com   Then: ollama pull ${MODEL}"
  exit 1
}

echo "[*] Sampling up to 3 existing seeds from ${CORPUS_DIR} for format context..."
SAMPLE=""
i=0
for f in "$CORPUS_DIR"/*; do
  [ -f "$f" ] || continue
  SAMPLE="${SAMPLE}--- $(basename "$f") ---
$(head -c 500 "$f")

"
  i=$((i + 1))
  [ "$i" -ge 3 ] && break
done

PROMPT=$(cat <<PROMPT_EOF
This is a php-fuzzer target definition (it shows exactly which library
function receives the fuzzed bytes, and which exceptions are expected vs.
which count as real bugs):

$(cat "$TARGET_FILE")

Existing seed inputs already in its corpus, for format context:

${SAMPLE}

Generate ${COUNT} NEW seed inputs for this exact input format — diverse,
syntactically plausible, biased toward edge cases that are historically
tricky for this class of parser: deep nesting, unusual whitespace or control
characters, boundary-length values, mixed encodings, and inputs that sit near
where error-handling branches would trigger. Do not just repeat the existing
examples with trivial changes.

Output ONLY the ${COUNT} seeds, each wrapped in its own block exactly like:
<<<SEED>>>
(seed content here)
<<<END>>>
Nothing else — no explanation, no numbering, no markdown fences around the blocks.
PROMPT_EOF
)

echo "[*] Asking ${MODEL} for ${COUNT} seeds..."
RESPONSE=$(curl -sS http://localhost:11434/api/generate \
  -d "$(jq -n --arg model "$MODEL" --arg prompt "$PROMPT" \
        '{model: $model, prompt: $prompt, stream: false}')" \
  | jq -r '.response // empty')

if [ -z "$RESPONSE" ]; then
  echo "[!] Empty response from Ollama — check 'ollama list' includes ${MODEL}."
  exit 1
fi

STAMP=$(date +%s)
echo "$RESPONSE" | awk -v dir="$CORPUS_DIR" -v prefix="localmodel-${STAMP}" '
  /<<<SEED>>>/ { capture=1; buf=""; next }
  /<<<END>>>/  { capture=0; n++; file=dir "/" prefix "-" n ".seed"; print buf > file; close(file); next }
  capture { buf = buf $0 "\n" }
'

NEW_COUNT=$(ls "${CORPUS_DIR}/localmodel-${STAMP}-"*.seed 2>/dev/null | wc -l | tr -d ' ')
echo "[✓] Added ${NEW_COUNT} new seed(s) to ${CORPUS_DIR}/"
echo "    These are unreviewed model output — skim them, then let a real"
echo "    fuzzing run (not this script) decide if they're actually useful:"
echo "    docker run --rm -v \"\$PWD/findings:/fuzz/findings\" sbom-fuzzer ${TARGET}"
