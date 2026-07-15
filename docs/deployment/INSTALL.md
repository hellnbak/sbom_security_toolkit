# Install and Upgrade

## Local install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
make doctor
make ui-server
```

The packaging-tool upgrade is limited to the virtual environment. v2.14.2 includes a compatibility `setup.py` for environments that begin with Apple pip 21.2.x.

## Upgrade an existing Git checkout

Do not mirror a release archive with a delete option. Apply the release with the non-destructive updater supplied in the extracted v2.14.2 package:

```bash
/path/to/sbom-security-toolkit-v2.14.2/scripts/apply-release-safe.sh \
  /path/to/sbom_security_toolkit

cd /path/to/sbom_security_toolkit
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
make reconciled-test
make preflight-release
```

See [`UPGRADE.md`](../../UPGRADE.md) for recovery from v2.14.1 and clean-clone instructions.

## Self-hosted cloud

Use the Docker Compose cloud file or Kubernetes/Helm scaffolds. Deploy behind authentication and TLS. Use secret references instead of raw tokens in configuration files.
