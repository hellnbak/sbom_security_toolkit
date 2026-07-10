# Installation

## Local editable install

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
make setup
source .venv/bin/activate
sst --help
```

## Run the local workbench

```bash
make ui-server
```

Open <http://127.0.0.1:8080>.

## Docker local workbench

```bash
make docker-build
make docker-ui
```

The default container binds to `127.0.0.1:8080` and stores generated workbench data in a local volume.

## Optional tools

The toolkit works without external scanners, but some workflows become richer when these are installed:

- Syft
- Trivy
- Grype
- OSV-Scanner
- Docker
- cosign
- OpenSSF Scorecard
