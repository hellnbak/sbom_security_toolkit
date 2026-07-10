#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
cd "$ROOT"
# Remove generated Python cache files that validation may have created.
find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true
fail=0

check() {
  local name="$1"; shift
  echo "[preflight] $name"
  if ! "$@"; then
    echo "[preflight] FAILED: $name" >&2
    fail=1
  fi
}

check "python cache files" bash -c '! find . -type d -name __pycache__ -o -type f \( -name "*.pyc" -o -name "*.pyo" \) | grep -q .'
check "generated reports excluded" bash -c '! find reports release-evidence fuzzing/findings fuzzing/reports fuzzing/generated-corpus ui/storage/jobs ui/storage/uploads -mindepth 1 2>/dev/null | grep -v "\.gitkeep$" | grep -q .'
check "large files over 20MB" bash -c '! find . -type f -size +20M ! -path "./.git/*" | grep -q .'

SECRET_RE='AKIA|ASIA|aws_secret|api[_-]?key[[:space:]]*[=:][[:space:]]*[A-Za-z0-9_\-]{16,}|github_pat_|ghp_|BEGIN (RSA|OPENSSH|DSA|EC|PRIVATE) KEY|xox[baprs]-|sk-[A-Za-z0-9]{20,}|password[[:space:]]*[=:][[:space:]]*[^$<{]'
if grep -RInE "$SECRET_RE" . \
  --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules --exclude-dir=reports --exclude-dir=release-evidence \
  --exclude='*.md' --exclude='*.json' --exclude='preflight-release.sh' --exclude='validators.py' --exclude='test_ai_fuzz.py' >/tmp/sst-secret-scan.txt; then
  echo "[preflight] potential secrets:" >&2
  cat /tmp/sst-secret-scan.txt >&2
  fail=1
else
  echo "[preflight] secret scan ok"
fi

COMPANY_RE='Cars Commerce|Cars\.com|Dealer Inspire|AccuTrade|JPMorgan|Chase Inventory|Cox Automotive|Autotrader|KBB|Carfax|CarGurus|vAuto|HomeNet|Max Digital|Dealer Club|D2C Servers|Chicago-Datacenter'
if grep -RInE "$COMPANY_RE" . --exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules --exclude='preflight-release.sh' >/tmp/sst-company-scan.txt; then
  echo "[preflight] company-specific terms found:" >&2
  cat /tmp/sst-company-scan.txt >&2
  fail=1
else
  echo "[preflight] company term scan ok"
fi

exit "$fail"
