# Install and Upgrade

## Local install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
make doctor
make ui-server
```

## Upgrade

```bash
git pull
pip install -e .
make test-fast
make test-integration-offline
```

## Self-hosted cloud

Use the Docker Compose cloud file or Kubernetes/Helm scaffolds. Deploy behind authentication and TLS. Use secret references instead of raw tokens in config files.
