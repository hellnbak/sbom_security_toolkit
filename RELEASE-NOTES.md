# Release Notes

## v2.7.1 — Workbench Reports Viewer

- Added a Workbench **Reports** page to browse generated reports without downloading full evidence bundles.
- Added report indexing for `reports/`, `release-evidence/`, `ui/storage/jobs/*/results`, `findings/`, `fuzzing/reports/`, and `projects/`.
- Added safe previews for JSON, SARIF, Markdown, text, CSV, YAML, XML, and HTML artifacts.
- Added `sst reports index`, `sst reports view`, `make reports-index`, and `make reports-view`.
- Added `docs/reporting/REPORTS-VIEWER.md`.

## v2.7.0 — Findings & Remediation Operations

- Added central findings store with stable fingerprints and repeated-scan deduplication.
- Added finding lifecycle statuses, owner assignment, ticket links, and evidence metadata.
- Added SLA reports, dashboards, exports, and next-best-action queue.
- Added risk acceptance and suppression workflows with owner, justification, expiry, and reopen conditions.
- Added remediation-plan generation with upgrade/replacement guidance, fix risk, verification steps, rollback notes, compensating controls, and acceptance criteria.
- Added remediation ticket templates, campaigns, owner routing from `owners.yml`, and fix-verification workflow.
- Added Workbench Findings page plus CLI/Make targets.

## v2.6.0 — Live Integrations + Operational Workflows

- Added live/dry-run Jira and DefectDojo integration workflows.
- Added Slack, webhook, and email notification delivery with dry-run default.
- Added GitHub PR/check summary generation, scheduler runner, job lifecycle helpers, evidence retention cleanup, and integration smoke tests.

## v2.5.0 — Production Integrations + Deployment Readiness

- Added SARIF, OpenVEX, Jira, DefectDojo, CI/CD, GitHub App, Kubernetes/Helm, OIDC, worker-limit, notification, and demo scaffolds.
- Added Workbench Integrations page and production integration documentation.

## v2.4.0 - Enterprise Cloud Hardening

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
