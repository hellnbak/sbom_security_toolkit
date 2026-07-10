# Release Notes

## v2.9.0 — Release Assurance and Governance

SBOM Security Toolkit v2.9.0 adds a governed release-decision layer on top of the existing SBOM generation, analysis, fuzzing, remediation, integration, and AI-reporting capabilities.

### Release assurance

- Added `sst assurance` and `sst release-assurance`.
- Added deterministic decisions: `PASS`, `PASS_WITH_WARNINGS`, `APPROVAL_REQUIRED`, `BLOCK`, `INCOMPLETE_EVIDENCE`, and `ERROR`.
- Added stable exit codes: `0`, `2`, `3`, `4`, `5`, and `10`.
- Added configurable CI failure thresholds with `--fail-on block|approval|warning|never`.
- Added policy evaluation for severity, fix availability, CISA KEV status, EPSS, CVSS, finding age, direct dependencies, reachability, and environment.
- Added explicit evidence requirements for provenance, artifact signatures, SBOM signatures, and builder identity.
- Added JSON and Markdown policy-decision outputs under `reports/release-assurance/`.

### Risk exceptions and governance

- Added `sst risk-exceptions` and `sst exceptions`.
- Added exception creation, approval, listing, expiration detection, and revocation.
- Added scoped exceptions for project, vulnerability, component, package URL, and policy rule.
- Added requestor, approver, justification, compensating controls, expiry, and append-only history fields.
- Expired, revoked, or unapproved exceptions no longer suppress blocking policy results.

### VEX and reachability

- Added VEX-aware release evaluation.
- Findings marked not affected, false positive, resolved, or fixed can be excluded from applicable policy decisions.
- Added reachability-aware and direct/transitive dependency policy matching.

### Provenance and integrity

- Added `sst provenance`.
- Added SHA-256 correlation between release artifacts, SBOMs, and SLSA/in-toto-style provenance subjects.
- Added builder identity extraction.
- Added optional cosign blob verification for artifacts and SBOMs when signatures and a verification key are supplied.
- Added machine-readable provenance verification output.

### Release evidence

- Added `sst evidence-bundle`.
- Added versioned release-evidence directories with `manifest.json` and `checksums.txt`.
- Added SHA-256 hashes and file sizes for included evidence.
- Added optional cosign signing of the evidence manifest.

### Organizational context

- Added `sst org-model`.
- Added organization, business unit, application, service, repository, and artifact hierarchy support.
- Added ownership, environment, business criticality, internet exposure, data classification, regulatory scope, support tier, runtime platform, and production URL context fields.

### CI/CD and documentation

- Added GitHub Actions and GitLab CI release-assurance templates.
- Added production release-policy examples and policy-decision schema support.
- Updated package version to `2.9.0`.
- Added release-assurance regression tests and packaging/version checks.
- Updated README, changelog, roadmap, and release documentation for the v2.9.0 release.

### Validation

- Python compilation validation passed.
- CLI command/help validation passed.
- Fifteen targeted core, packaging, version, and release-assurance tests passed.
- The broader suite reached long-running fuzz/workbench integration tests and exceeded the available execution window; no failure was observed before timeout.

### Compatibility

Existing SBOM analysis, repository intake, supplier intake, project history, findings/remediation, integrations, fuzzing, lifecycle intelligence, Snyk ingestion, Workbench, and evidence-grounded AI-reporting workflows remain available.

## v2.8.1 - Snyk SBOM Connector

- Added dry-run-first Snyk connector configuration with token references only.
- Added Snyk connection test and Snyk project SBOM pull commands.
- Added Snyk-vs-local SBOM comparison reports for coverage drift and version mismatches.
- Added Workbench Integrations configuration controls for Snyk org ID, project ID, token environment variable, SBOM format, and local comparison path.
- Added Make targets: `snyk-config`, `snyk-test`, `snyk-pull-sbom`, `snyk-compare`, and `snyk-smoke`.
- Added `docs/integrations/SNYK-SBOM-CONNECTOR.md`.

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
