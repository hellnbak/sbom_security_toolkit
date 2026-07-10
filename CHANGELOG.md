# Changelog

## 2.11.0 - User Experience

- Added audited Security Controls GUI for release assurance, VEX, provenance, evidence generation, organization context, and remediation planning.
- Fixed evidence-bundle download handling when a bundle has not yet been generated.
- Added full primary-route HTTP smoke coverage and GUI-to-backend feature coverage tests.
- Verified all 66 tests in bounded deterministic groups.

- Redesigned Workbench application shell and responsive navigation.
- Added overview dashboard, release decisions, action center, exceptions, evidence, and global search pages.
- Added connector health visibility and guided first-run states.
- Reorganized advanced tools using progressive disclosure.
- Updated product documentation and version metadata.

## 2.10.0 - Connector Platform

- Added a reusable connector SDK and registry.
- Added unified Snyk, Dependency-Track, DefectDojo, GitHub, and webhook connectors.
- Added dry-run-first test, discovery, and synchronization workflows.
- Added capability reporting, health artifacts, retries, pagination, timeout controls, and guarded writes.
- Added connector configuration and health controls to the Workbench and static dashboard.
- Added connector documentation, examples, Make targets, and offline end-to-end tests.

## 2.9.0 - Release Assurance and Governance

- Added a unified policy-as-code release assurance engine with stable PASS, warning, approval, block, incomplete-evidence, and error decisions.
- Added scoped, approved, expiring risk exceptions with audit history and compensating controls.
- Added VEX-aware and reachability-aware policy evaluation.
- Added artifact/SBOM digest verification, SLSA-style provenance validation, and optional cosign verification.
- Added organization, business-unit, application, service, repository, and artifact security context.
- Added hash-manifested and optionally signed evidence bundles.
- Added GitHub Actions and GitLab CI release-gate examples.
- Added policy-decision schema, production policy, examples, documentation, and regression tests.
- Preserved the existing policy, project, remediation, integration, reporting, and fuzzing commands for compatibility.

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

## v2.4.0 - Enterprise cloud hardening

- Added `sbomops.enterprise` for self-hosted team controls.
- Added `sst enterprise ...` CLI support for auth/RBAC scaffolding, users, roles, schedules, notifications, secret references, API tokens, audit logs, health checks, and first-run setup.
- Added Workbench **Admin** page for first-run setup, user/RBAC management, scheduled scans, notifications, secret references, service-account tokens, and audit-log review.
- Added enterprise generated config storage under `configs/generated/enterprise/`.
- Added append-only audit logging under `ui/storage/enterprise/audit.log.jsonl`.
- Added `docs/enterprise/ENTERPRISE-CLOUD-HARDENING.md`.
- Added Make helpers: `enterprise-health`, `enterprise-setup`, `enterprise-list`, `enterprise-audit-list`, `enterprise-schedule`, `enterprise-notification`, `enterprise-secret-ref`, and `enterprise-api-token`.
- Updated README and release notes to document the local-first plus self-hosted enterprise model.

## v2.3.1 - GUI-managed configuration

- Added Workbench Settings page for policy, AI provider, fuzzing profile, project default, and cloud setting configuration.
- Added generated YAML preview and import support for GUI-managed configuration.
- Added `sbomops.config_manager` and `sst config ...` commands.
- Added Make helpers for generating and validating common configuration files.
- Updated README and release notes for the configuration UX refresh.


## v2.3.0 - Project Risk Dashboard, All-Actions Scan, and Self-Hosted Cloud Mode

- Added local project workspaces, project history recording, delta reports, and trend dashboards.
- Added release-decision workflow, evidence viewer, GitHub Actions workflow generator, policy tuning helper, dependency owner template, and AI executive-summary scaffold.
- Added Workbench Projects page.
- Added main SBOM workflow option: Full SBOM analysis + every action + all fuzzing scenarios.
- Added UI controls for fuzz time per step/library and fuzz targets for the all-actions scan.
- Added optional self-hosted cloud mode scaffolding while preserving local-first defaults.
- Added `docker/docker-compose.cloud.yml` with Workbench API/UI, generic worker, fuzzing worker, Postgres, Redis, and MinIO/S3-compatible object storage.
- Added `cloud/.env.example`, `docs/cloud/CLOUD-MODE.md`, and AWS self-hosting policy notes under `cloud/aws/`.
- Added `sst cloud init-config`, `sst cloud doctor`, `sst cloud schedule-template`, `make cloud-config`, `make cloud-doctor`, `make cloud-compose-up`, and `make cloud-worker-smoke`.
- README updated to describe local-first plus cloud-capable deployment.

## v2.2.6 - AI-Enhanced Full SBOM Analysis and Bedrock Provider

- Added optional AI-assisted fuzz case generation to Full SBOM Analysis.
- Added suggest-only and generate-and-run-validated-cases modes.
- Added deterministic validation/execution for AI-derived fuzz cases.
- Added AWS Bedrock as an optional AI provider in the Fuzzing Lab and main analysis UI.
- Added Bedrock provider support through boto3 when installed and configured.
- Added Bedrock docs and optional AWS AI requirements file.
- Added `make ai-fuzz-analysis` and `sst ai-fuzz-analysis`.

## v2.2.5 - Structure-Preserving Fuzzing Stability

- Fixed structure-preserving SBOM mutation for normalized CycloneDX XML inputs whose component `hashes` field is represented as a count/integer.
- Improved `bom_ref` / `bom-ref` handling in the SBOM mutator.
- Verified the Workbench `test-all-components` debugging workflow passes the previously failing mutation step.

## v2.2.4 - Dependency Health UI Clarity

- Made unsupported/out-of-date dependency analysis easier to find in the local Workbench workflow dropdown.
- Added the same clarity to Repository Intake for dependency-health-only runs.
- Added stale-threshold controls to the uploaded SBOM workflow form.

## v2.2.3 - Fuzzing Workflow Verification and Workbench Stability

- Verified major Fuzzing Lab workflows against CycloneDX JSON and CycloneDX XML inputs.
- Added `scripts/smoke-fuzz-workflows.sh` and `make fuzz-workflow-smoke` for local regression coverage of fuzzing modes.
- Fixed `make fuzz-evil-supplier`, which used an obsolete argument.
- Made Docker-dependent fuzzing modes skip cleanly when Docker is unavailable.
- Fixed timed fuzzing variable propagation for `TIME_BUDGET` and `COUNT`.
- Changed workbench status writes to atomic replacement so the UI does not read partially written `status.json` files.

## v2.2.2 - Fuzzing Observability and Evidence Status

- Added `fuzz-run-summary.json` and `fuzz-run-summary.md` to every Fuzzing Lab job.
- Evidence bundles now include final completed/failed job status instead of stale `running` status.
- Metamorphic SBOM fuzzing reports input stats, transform count, generated artifacts, and guidance explaining deterministic semantic checks versus timed all-mode fuzzing.
- CycloneDX XML inputs are normalized before JSON-oriented semantic fuzzing workflows.

## v2.2.1 - Dependency Health and Unsupported Dependency Review

- Added `dependency-health` workflow for uploaded SBOMs and repository-generated SBOMs.
- Added `repo-dependency-health` for repository intake pipelines.
- Added UI support for dependency-health checks, stale-day threshold configuration, and optional registry enrichment.
- Added optional enrichment for npm, PyPI, crates.io, and Packagist.
- Reports are generated as JSON, Markdown, and CSV.
- Uses conservative interpretation: stale release activity is a review trigger, not an automatic EOL conclusion.

## v2.2.0 - Repository Intake and SBOM Build Pipeline

- Added repository intake from local paths, uploaded archives, HTTPS GitHub URLs, and private GitHub repositories using a token.
- Added static ecosystem detection across common package managers and build systems.
- Added internal CycloneDX fallback generation plus orchestration for Syft, cdxgen, Trivy, Grype, and OSV-Scanner when installed.
- Added SBOM generator comparison, repository vulnerability scanning, optional fuzzing of generated SBOMs, and repository evidence bundles.
- Added Repository Intake tab in the local workbench UI.
- GitHub tokens are held only in process memory for the current job and are not written to logs, status files, reports, or evidence bundles.

## v2.1.1 - Fuzzing Lab Time Limits and Format-Tolerant Runs

- Restored browser controls for fuzzing time limits.
- Added `fuzz-all-timed` to run available fuzzing workflows for a user-defined time budget per step/library.
- Normalized supported non-JSON SBOMs, including CycloneDX XML, before JSON-oriented fuzzing workflows.

## Earlier releases

See `RELEASE-NOTES.md` for the full historical release narrative covering v1.x, v2.0.x, and v2.1.0.

### v2.3.0 validation refresh - timed fuzzing runner hardening

- Added `scripts/run-timed-fuzz-suite.py` as the shared CLI/Workbench runner for broad time-boxed fuzzing.
- Added Workbench `test-all-components` debug workflow parity so the previously referenced debug flow is available in the UI.
- Updated `make fuzz-all-timed` to route through the shared timed runner and honor `LIBRARY_TARGETS` such as `sbom`, `scanner`, `ai`, or `all`.
- Verified core SBOM, repository-intake, dependency-health, project, cloud, and Workbench fuzzing paths in a clean package workspace.
