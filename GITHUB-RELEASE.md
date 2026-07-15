# GitHub Release Procedure for v2.14.2

## Recommended: publish from a clean clone

Keep the currently modified checkout as a backup until the release branch has been validated.

```bash
cd ~/Downloads
mv sbom_security_toolkit sbom_security_toolkit-v2141-backup

git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
git fetch origin --tags
git checkout main
git pull --ff-only origin main
git checkout -b release/v2.14.2
```

Extract the v2.14.2 archive beside the clone and apply it without deleting repository-only files:

```bash
cd ~/Downloads/sbom-security-toolkit-v2.14.2
./scripts/apply-release-safe.sh ~/Downloads/sbom_security_toolkit
```

## Install and validate

```bash
cd ~/Downloads/sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"

make reconciled-test
make preflight-release
make demo-live
make preflight-release
```

The second preflight confirms that untracked demo output is ignored correctly.

Review the release diff:

```bash
git status --short
git diff --stat
git diff
```

Confirm that valid v2.9-v2.13 files are present, generated jobs are ignored, and no private configuration or evidence is staged.

## Commit and push

```bash
git add -A
git status --short
git commit -m "Release v2.14.2 GitHub reconciliation hotfix"
git push -u origin release/v2.14.2
```

Create and merge a pull request into `main`. After merge:

```bash
git checkout main
git pull --ff-only origin main
git tag -a v2.14.2 -m "SBOM Security Toolkit v2.14.2"
git push origin v2.14.2
```

Create the GitHub release from tag `v2.14.2` and attach:

- `sbom-security-toolkit-v2.14.2-github-reconciled-hotfix.zip`
- `sbom-security-toolkit-v2.14.2-github-reconciled-hotfix.zip.sha256`

## In-place repair of the current checkout

The safe updater can also repair the checkout that was modified by v2.14.1:

```bash
cd ~/Downloads/sbom-security-toolkit-v2.14.2
./scripts/apply-release-safe.sh ~/Downloads/sbom_security_toolkit
```

It records the existing Git status and binary diff before copying files. It does not delete destination-only files. Review the resulting diff carefully before committing.
