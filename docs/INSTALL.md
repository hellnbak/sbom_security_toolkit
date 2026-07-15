# Installation

## Requirements

- Python 3.9 or newer
- macOS or Linux
- Optional external scanners such as Syft, Trivy, Grype, and OSV-Scanner

## Recommended local installation

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
sst --help
sst version
```

The pip upgrade occurs only inside `.venv`. v2.14.2 also includes `setup.py` for compatibility with Apple systems whose starting pip version is 21.2.x.

The bundled helper performs the same steps:

```bash
./scripts/bootstrap-macos.sh
source .venv/bin/activate
```

## Validate dependencies

```bash
make check-runtime-deps
make reconciled-test
```

A missing `PyYAML` dependency now produces a direct installation error instead of being misreported as malformed JSON.

## Run the local Workbench

```bash
make ui-server
```

Open <http://127.0.0.1:8080>.

## Run the live offline demo

```bash
make demo-live
```

This creates local runtime data under ignored Workbench directories. It does not require network access or credentials.

## Docker local Workbench

```bash
make docker-build
make docker-ui
```

The default container binds to `127.0.0.1:8080` and stores generated Workbench data in a local volume.

## Optional tools

The toolkit works without external scanners, but some workflows become richer when these are installed:

- Syft
- Trivy
- Grype
- OSV-Scanner
- Docker
- cosign
- OpenSSF Scorecard
