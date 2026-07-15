# Upgrade to v2.14.2

v2.14.2 is a complete hotfix and reconciliation release. It supersedes the v2.14.0 overlay and the v2.14.1 archive.

## Why v2.14.2 is required

v2.14.1 had four release-engineering defects:

1. It lacked a compatibility `setup.py`, so editable installation failed with Apple's pip 21.2.4.
2. Its reduced test set missed APIs and files introduced in repository releases v2.9 through v2.13.
3. Its preflight rejected harmless local demo output rather than checking whether that output was tracked or packaged.
4. The published GitHub update example used `rsync --delete`, which could delete valid repository-only documentation, policies, schemas, CI files, examples, and tests.

v2.14.2 corrects all four issues.

## Recommended recovery from the failed v2.14.1 copy

The safest path is a fresh clone. Keep the damaged directory temporarily so any private configuration can be recovered deliberately.

```bash
cd ~/Downloads
mv sbom_security_toolkit sbom_security_toolkit-v2141-backup

git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
git checkout -b release/v2.14.2
```

Extract v2.14.2 beside the clone, then apply it with the included non-destructive updater:

```bash
cd ~/Downloads/sbom-security-toolkit-v2.14.2
./scripts/apply-release-safe.sh ~/Downloads/sbom_security_toolkit
```

The updater:

- records the destination's current `git status` and binary patch;
- copies release files without `--delete`;
- does not touch `.git`, `.venv`, jobs, uploads, demo state, reports, projects, or local evidence;
- restores repository capability files that v2.14.1 accidentally removed;
- compiles the resulting Python source as a basic sanity check.

## In-place recovery

The same updater can repair the already modified checkout because v2.14.2 contains the restored files. Back up any private configuration first:

```bash
cd ~/Downloads/sbom-security-toolkit-v2.14.2
./scripts/apply-release-safe.sh ~/Downloads/sbom_security_toolkit
```

Do not run another `rsync --delete` command.

## Install or reinstall

```bash
cd ~/Downloads/sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
sst version
```

Expected version: `2.14.2`.

## Validate

```bash
make reconciled-test
make preflight-release
make demo-live
make preflight-release
```

The second preflight is intentional: it verifies that a completed demo does not make the source tree unreleasable.

## Review before committing

```bash
git status --short
git diff --stat
git diff
```

Generated jobs and demo files should be ignored. Valid v2.9-v2.13 repository files should be present rather than deleted.

## Local data and secrets

Preserve only the configuration and evidence you intentionally need. Never commit production SBOMs, customer data, generated reports, tokens, private package inventories, or local Workbench state. Connector configuration must reference environment variables or a supported secret manager rather than storing secret values.
