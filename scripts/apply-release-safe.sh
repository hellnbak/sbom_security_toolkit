#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/apply-release-safe.sh /path/to/sbom_security_toolkit

Applies this release over an existing Git checkout without deleting files that
exist only in the checkout. Existing Git changes are recorded to a patch and
status file in the target's parent directory before files are copied.
USAGE
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_ROOT="$(cd "$1" 2>/dev/null && pwd || true)"
[[ -n "$TARGET_ROOT" && -d "$TARGET_ROOT" ]] || { echo "Target directory not found: $1" >&2; exit 2; }
[[ -d "$TARGET_ROOT/.git" ]] || { echo "Target is not a Git checkout: $TARGET_ROOT" >&2; exit 2; }
[[ -f "$TARGET_ROOT/pyproject.toml" || -f "$TARGET_ROOT/setup.py" ]] || { echo "Target does not look like SBOM Security Toolkit" >&2; exit 2; }
[[ "$SOURCE_ROOT" != "$TARGET_ROOT" ]] || { echo "Source and target are the same directory; nothing to apply." >&2; exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_BASE="$(dirname "$TARGET_ROOT")/sbom-toolkit-pre-v2.14.2-$STAMP"
git -C "$TARGET_ROOT" status --short > "${BACKUP_BASE}.status.txt"
git -C "$TARGET_ROOT" diff --binary > "${BACKUP_BASE}.patch" || true

echo "Recorded existing Git status: ${BACKUP_BASE}.status.txt"
echo "Recorded existing tracked-file diff: ${BACKUP_BASE}.patch"
echo "Applying v2.14.2 without --delete..."

# A tar stream is used so destination-only files are preserved. The exclusions preserve the
# destination's Git metadata, virtual environment, and runtime-generated data.
tar -C "$SOURCE_ROOT" -cf - \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='.pytest_cache' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='reports' \
  --exclude='release-evidence' \
  --exclude='projects' \
  --exclude='.upgrade-manifests' \
  --exclude='ui/storage/jobs/*' \
  --exclude='ui/storage/uploads/*' \
  --exclude='ui/storage/demo' \
  . | tar -C "$TARGET_ROOT" -xf -

mkdir -p "$TARGET_ROOT/ui/storage/jobs" "$TARGET_ROOT/ui/storage/uploads"
touch "$TARGET_ROOT/ui/storage/jobs/.gitkeep" "$TARGET_ROOT/ui/storage/uploads/.gitkeep"

python3 -m compileall -q "$TARGET_ROOT/sbomops" "$TARGET_ROOT/tests"

echo
echo "v2.14.2 files applied successfully. No destination-only files were deleted."
echo "Next commands:"
echo "  cd '$TARGET_ROOT'"
echo "  source .venv/bin/activate  # or create it first"
echo "  python -m pip install --upgrade pip setuptools wheel"
echo "  python -m pip install -e '.[dev]'"
echo "  make reconciled-test"
echo "  make preflight-release"
echo "  git status --short"
