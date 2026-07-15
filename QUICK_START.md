# Quick Start

## Supported environment

- Python 3.9 or newer
- macOS, Linux, or a compatible container environment
- Network access is needed only to install Python dependencies or use live connectors

## Install on macOS or Linux

The bootstrap script upgrades the virtual environment's packaging tools before installing the toolkit. It does not modify the system Python installation.

```bash
python3 --version
./scripts/bootstrap-macos.sh
source .venv/bin/activate
sst version
```

Expected version: `2.14.2`.

Equivalent manual commands:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
sst version
```

A compatibility `setup.py` is included so Apple environments still using pip 21.2.x can perform an editable install. Upgrading pip inside the virtual environment remains recommended.

## Run the offline live demo

```bash
make doctor
make demo-live
make ui-server
```

Open `http://127.0.0.1:8080`, then select **Demo** or **Jobs**. The demo uses a clearly marked synthetic CycloneDX SBOM and the normal job runner. It creates real status transitions, logs, analysis artifacts, an automatic engineering report, and an evidence archive.

## Analyze your own SBOM

Use **Quick Start**, **Guided Workflows**, or the upload page. For the CLI:

```bash
make sbom-score SBOM=/path/to/bom.json
make dependency-health SBOM=/path/to/bom.json
```

## Analyze a repository

```bash
make repo-intake REPO_SOURCE=/path/to/repository
```

For a private GitHub repository, keep the token in an environment variable:

```bash
export GITHUB_TOKEN=github_pat_xxx
make repo-intake \
  REPO_SOURCE=https://github.com/org/private-repo.git \
  ALLOW_REMOTE=1 \
  GITHUB_TOKEN_ENV=GITHUB_TOKEN
```

## Generate another report version

Every completed Workbench run receives a default engineering report. Generate an executive version from the same evidence without rerunning the scan:

```bash
make report-variant \
  JOB_DIR=ui/storage/jobs/<job-id> \
  REPORT_VARIANT=executive
```

The job evidence ZIP is refreshed automatically.

## Validate the installation

```bash
make reconciled-test
make preflight-release
make demo-live
```

`preflight-release` ignores local, untracked demo output. It fails only when generated runtime data is tracked by Git or included in the release manifest.
