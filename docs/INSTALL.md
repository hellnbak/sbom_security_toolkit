# Installation

## Requirements

- Python 3.10 or newer
- Git
- Optional: Docker, Syft, Trivy, Grype, OSV-Scanner, cosign, OpenSSF Scorecard

## Local editable install

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -e ".[dev]"

sst version
sst doctor
```

## Run the Workbench

```bash
sst workbench
```

Open <http://127.0.0.1:8080/dashboard>.

Alternative Make target:

```bash
make ui-server
```

## Docker local Workbench

```bash
make docker-build
make docker-ui
```

The default local deployment binds to `127.0.0.1:8080` and stores generated data in local paths or volumes.

## Upgrade an existing clone

Apply release contents to the repository root while preserving `.git`, then reinstall:

```bash
source .venv/bin/activate
pip install -e ".[dev]"
sst version
```

Review `RELEASE-NOTES.md` and run the validation commands in `VALIDATION.md` before deployment.
