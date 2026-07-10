# Self-hosted cloud mode

SBOM Security Toolkit remains **local-first**. Cloud mode is optional and is intended for teams that need scheduled scans, shared project history, retained evidence bundles, and long-running fuzzing workers.

## Deployment modes

1. **Local Workbench** — single-user, filesystem storage, no auth, binds to `127.0.0.1`.
2. **Self-hosted server** — API/UI plus Postgres, Redis, object storage, and workers.
3. **Managed service** — not included; the project is prepared for this later but does not require it.

## Start the self-hosted stack locally

```bash
cp cloud/.env.example cloud/.env
# edit secrets before real use
set -a; source cloud/.env; set +a
docker compose -f docker/docker-compose.cloud.yml up --build
```

The compose stack includes:

- Workbench web/API
- generic worker scaffold
- fuzzing worker scaffold
- Postgres
- Redis
- MinIO for S3-compatible evidence storage

## Safety defaults

Cloud mode should preserve the same safety model as local mode:

- Do not execute repository code by default.
- Do not run install scripts by default.
- Do not send SBOMs/source to external AI providers unless explicitly enabled.
- Do not log GitHub tokens, AWS credentials, or provider secrets.
- Run long fuzzing jobs in workers, not in the API container.
- Use object storage encryption and least-privilege IAM policies.

## Useful commands

```bash
sst cloud init-config --output cloud/sst-cloud-config.json
sst cloud doctor
sst cloud schedule-template --output cloud/run-scheduled-scan.sh
make cloud-config
make cloud-doctor
make cloud-compose-up
```

## Authentication

The initial cloud mode is a self-hosted scaffold. Use a reverse proxy, VPN, or private network boundary until you enable production-grade authentication. Future hardening can add OIDC/SAML, role-based access, and team workspaces.

## Secrets

Use environment variables for local testing and a proper secret manager for cloud deployments. On AWS, use IAM roles and Secrets Manager. Never place tokens in job options, URLs, reports, evidence bundles, or logs.
