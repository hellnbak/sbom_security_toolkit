# Release Notes

## v2.8.0 - Productization, QA, and Demo Readiness

- Added `sbomops.productization` helpers for doctor, first-run setup, demo generation, release gate, install notes, and security hardening checklist output.
- Added Make targets: `test-fast`, `test-integration-offline`, `test-fuzz-smoke`, `test-release`, `test-all`, `doctor`, `first-run`, `demo-product`, `reset-demo`, `security-checklist`, and `install-notes`.
- Added GitHub issue templates, pull request template, CODEOWNERS, and CI workflow scaffold.
- Added `ROADMAP.md`, `docs/ARCHITECTURE.md`, `docs/demo/WALKTHROUGH.md`, `docs/qa/RELEASE-GATE.md`, `docs/deployment/INSTALL.md`, and `docs/product/FIRST-RUN.md`.
- Updated README to keep the product introduction, value proposition, quick start, and QA/release workflow at the top.

## v2.7.3 — AI Report Writer

- Added evidence-bound AI report writer for executive, engineering, supplier, release, fuzzing, lifecycle, and full security reports.
- Added deterministic fact extraction from SBOMs, findings, lifecycle outputs, release evidence, fuzzing summaries, SARIF/OpenVEX, project history, and generated reports.
- Added Markdown, HTML, JSON summary, prompt, metadata, and fact-bundle outputs in `reports/ai/`.
- Added Workbench **AI Reports** page and report viewer integration.
- Added prompt-only default mode and optional Bedrock/Ollama/GLM/OpenAI-compatible narrative generation.
- Added `sst ai-report`, `make ai-report`, `make ai-report-facts`, `make ai-report-templates`, and `make ai-report-smoke`.
- Added `docs/reporting/AI-REPORT-WRITER.md`.

# Release Notes

## v2.7.2 — Lifecycle Intelligence Sources

- Added lifecycle intelligence to dependency-health analysis.
- Added endoflife.date-style lifecycle source support for runtimes, operating systems, databases, frameworks, and platform components.
- Added source/status/confidence separation for EOL, deprecated/abandoned, stale review signals, unpinned versions, and unknown lifecycle status.
- Added offline lifecycle cache support and a tiny built-in cache for deterministic smoke tests.
- Added `lifecycle-intelligence.json` and `lifecycle-intelligence.md` report outputs.
- Added `sst lifecycle`, `sst lifecycle-intelligence`, and `make lifecycle-intelligence`.
- Added Workbench lifecycle source controls for SBOM upload and repository intake workflows.
- Added `docs/dependency-health/LIFECYCLE-INTELLIGENCE.md`.

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
