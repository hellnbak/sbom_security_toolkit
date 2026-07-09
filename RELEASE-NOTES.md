# v2.6.0 — Production Integrations + Deployment Readiness

- Added SARIF export for GitHub code scanning and compatible security tooling.
- Added OpenVEX generation for review-oriented vulnerability status workflows.
- Added Jira and DefectDojo export payload scaffolds.
- Added CI/CD template generation for GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite, and Azure DevOps.
- Added GitHub App configuration scaffold.
- Added Slack/webhook/email notification delivery with dry-run default.
- Added Kubernetes/Helm deployment scaffold.
- Added generic OIDC configuration scaffold.
- Added worker runtime limits for cloud/self-hosted worker safety.
- Added enterprise demo data generation.
- Updated README and production integration documentation.

# v2.4.0 - Enterprise Cloud Hardening

SBOM Security Toolkit v2.4.0 keeps the project local-first while adding self-hosted enterprise controls for teams.

## Highlights

- Workbench **Admin** page for first-run setup and team configuration.
- Auth/RBAC scaffolding with admin, maintainer, analyst, read-only, and service-account roles.
- User configuration with PBKDF2-SHA256 password hashes.
- Service-account API token generation with one-time display and SHA-256 hash-only storage.
- Scheduled scan definitions for workflows such as `analyze-everything`, repository intake, dependency health, and timed fuzzing.
- Notification target definitions for webhook, Slack, and email.
- Secret references for environment variables, AWS Secrets Manager, Docker secrets, Kubernetes secrets, and local encrypted-file placeholders.
- Append-only JSONL audit log for sensitive admin actions.
- Enterprise CLI and Make helpers.

## New commands

```bash
sst enterprise setup-wizard --admin-username admin --project-id default-project
sst enterprise create-user --username analyst --role analyst
sst enterprise schedule --name nightly-full-scan --workflow analyze-everything --cadence daily
sst enterprise notification --name security-alerts --type webhook --target-ref SST_WEBHOOK_URL
sst enterprise secret-ref --name github-token --provider env --reference GITHUB_TOKEN
sst enterprise api-token --name ci-service-account --owner github-actions --role service-account
sst enterprise audit-list --limit 25
sst enterprise health
```

## New Make targets

```bash
make enterprise-health
make enterprise-setup
make enterprise-list
make enterprise-audit-list
make enterprise-schedule
make enterprise-notification
make enterprise-secret-ref
make enterprise-api-token
```

## Safety notes

- Local mode remains the default.
- Secrets are references, not plaintext config values.
- API tokens are displayed once and then stored only as SHA-256 hashes.
- The enterprise layer is self-hosted scaffolding; full SaaS multi-tenancy and OIDC login enforcement are future layers.
