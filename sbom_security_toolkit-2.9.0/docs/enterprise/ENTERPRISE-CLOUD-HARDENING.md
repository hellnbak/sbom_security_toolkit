# Enterprise Cloud Hardening

SBOM Security Toolkit remains local-first, but v2.4.0 adds self-hosted cloud hardening scaffolding for teams that need shared projects, scheduled scans, auditability, and controlled access.

## What is included

- Local password auth scaffolding and OIDC-ready config
- RBAC role definitions for admin, maintainer, analyst, read-only, and service-account users
- User configuration with PBKDF2 password hashes
- Append-only audit log for sensitive operations
- Scheduled scan configuration
- Notification targets for webhooks, Slack, and email
- Secret reference management so secrets are not written into YAML
- API token/service account model that stores only SHA-256 token hashes
- Workbench Admin page for first-run setup and enterprise controls
- CLI automation through `sst enterprise ...`

## First-run setup

```bash
sst enterprise setup-wizard --admin-username admin --project-id default-project
```

The setup wizard creates:

```text
configs/generated/enterprise/auth.yml
configs/generated/enterprise/roles.yml
configs/generated/enterprise/users.yml
configs/generated/enterprise/schedules.yml
configs/generated/enterprise/notifications.yml
ui/storage/enterprise/audit.log.jsonl
```

If no admin password is provided, the CLI returns a one-time generated password. Store it immediately.

## Admin UI

Start the Workbench and open **Admin**:

```bash
make ui-server
```

The Admin page lets self-hosted operators create users, roles, schedules, notifications, secret references, and service-account API tokens without hand-editing YAML.

## Secrets model

The toolkit stores secret references, not secret values. Supported reference types include:

- environment variable
- AWS Secrets Manager
- Docker secret
- Kubernetes secret
- local encrypted file placeholder

Example:

```bash
sst enterprise secret-ref \
  --name github-token \
  --provider aws-secrets-manager \
  --reference arn:aws:secretsmanager:us-east-1:111122223333:secret:github-token \
  --purpose "private repository access"
```

## Audit log

Audit events are written as JSON lines:

```bash
sst enterprise audit-list --limit 25
```

Events include user changes, role changes, scheduled scan changes, notification changes, secret-reference changes, API token creation, and setup-wizard completion.

## Service accounts

```bash
sst enterprise api-token --name ci-scan-runner --owner github-actions --role service-account
```

The raw token is returned once. Only a SHA-256 hash is stored.

## Scope notes

v2.4.0 provides the enterprise control-plane scaffolding for self-hosted deployments. It intentionally does not force hosted SaaS behavior and does not store plaintext cloud or repository secrets. Full enforcement middleware, OIDC login flows, and multi-tenant SaaS billing can be layered on top of this foundation later.
