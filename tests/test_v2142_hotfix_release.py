from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_legacy_setuptools_entrypoint_reports_current_version():
    result = subprocess.run(
        ["python3", "setup.py", "--name", "--version"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert "sbom-security-toolkit" in lines
    assert "2.14.2" in lines


def test_release_restores_repository_capability_files():
    required = [
        ".github/workflows/test.yml",
        "ci/github-actions-release-assurance.yml",
        "ci/gitlab-release-assurance.yml",
        "docs/ACTIONABLE-WORKFLOWS.md",
        "docs/CONNECTORS.md",
        "docs/GUIDED-EXPERIENCE.md",
        "docs/operations/WORKBENCH-UX.md",
        "docs/ui/GUI-FEATURE-COVERAGE.md",
        "examples/connectors/snyk.yml",
        "examples/org/enterprise.yml",
        "policies/production-release-assurance.yml",
        "schemas/policy-decision.schema.json",
        "ui/storage/onboarding.json",
    ]
    missing = [name for name in required if not (ROOT / name).is_file()]
    assert not missing


def test_safe_updater_is_non_destructive():
    source = (ROOT / "scripts/apply-release-safe.sh").read_text(encoding="utf-8")
    assert "rsync --delete" not in source
    assert "tar -C" in source
    assert "git status --short" in source
    assert "diff --binary" in source


def test_runtime_paths_are_ignored():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for value in ["ui/storage/demo/*", "projects/*", ".upgrade-manifests/", "configs/generated/"]:
        assert value in ignored


def test_yaml_loader_has_clear_missing_dependency_error(tmp_path: Path):
    from sbomops import release_common

    policy = tmp_path / "policy.yml"
    policy.write_text("rules: []\n", encoding="utf-8")
    with mock.patch.object(release_common, "yaml", None):
        with pytest.raises(RuntimeError, match="PyYAML is not installed"):
            release_common.load_data(policy)


def test_preflight_allows_untracked_demo_output():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "scripts").mkdir()
        (root / "ui/storage/demo").mkdir(parents=True)
        (root / "source.txt").write_text("source\n", encoding="utf-8")
        (root / "ui/storage/demo/result.json").write_text("{}\n", encoding="utf-8")
        script = root / "scripts/preflight-release.sh"
        script.write_bytes((ROOT / "scripts/preflight-release.sh").read_bytes())
        script.chmod(0o755)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "source.txt", "scripts/preflight-release.sh"], cwd=root, check=True)
        result = subprocess.run([str(script), "."], cwd=root, text=True, capture_output=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "generated runtime files are untracked" in result.stdout
