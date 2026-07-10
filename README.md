# SBOM Security Toolkit

SBOM Security Toolkit is a local-first, cloud-capable workbench and release-assurance control plane for software supply-chain security. It helps teams generate, validate, fuzz, scan, explain, govern, monitor, and remediate SBOM risk across supplier intake, CI/CD release decisions, and ongoing project operations.

Current release: **v2.9.0 — Release Assurance and Governance**

## Why use this toolkit?

Use it when you need to answer practical questions:

- What is in this software and is its SBOM complete enough to trust?
- Are there critical vulnerabilities, known-exploited issues, unsupported dependencies, or scanner disagreements?
- Is a finding actually reachable or covered by valid VEX evidence?
- Can this release ship, does it need approval, or must it be blocked?
- Is an exception approved, scoped, justified, and still valid?
- Does the artifact match its provenance and signed SBOM evidence?
- Can audit-ready evidence and human-readable reports be generated from deterministic facts?

## What is new in v2.9.0

**Release Assurance and Governance** adds a unified decision layer that converts SBOM, vulnerability, VEX, exception, provenance, and organizational context into stable release outcomes.

- Policy-as-code decisions: `PASS`, `PASS_WITH_WARNINGS`, `APPROVAL_REQUIRED`, `BLOCK`, `INCOMPLETE_EVIDENCE`, and `ERROR`.
- Stable CI exit codes and configurable failure thresholds.
- Auditable risk exceptions with approval, compensating controls, expiration, revocation, and history.
- VEX-aware suppression and reachability-aware policy matching.
- SLSA/in-toto-style provenance subject validation and optional cosign verification.
- Organization, business-unit, application, service, repository, artifact, ownership, criticality, exposure, and regulatory context.
- Independently verifiable release evidence bundles with SHA-256 manifests and optional cosign signing.
- GitHub Actions and GitLab CI release-gate templates.
- New production policy examples, decision schemas, tests, and documentation.

## Core v2.9.0 commands

```bash
# Evaluate release evidence against policy
sst assurance \
  --policy policies/production-release.yml \
  --findings reports/findings.json \
  --vex reports/openvex.json \
  --exceptions governance/exceptions.yml \
  --provenance reports/provenance/provenance-verification.json \
  --context governance/context.yml \
  --fail-on block

# Manage risk exceptions
sst risk-exceptions create --project payments-api \
  --vulnerability CVE-2026-12345 \
  --justification "No compatible patched version is available" \
  --compensating-control "Service is not internet accessible" \
  --requestor security-team \
  --expires 2026-08-31

sst risk-exceptions approve RISK-20260710-ABC123 --approver security-architecture

# Verify artifact, SBOM, and provenance integrity
sst provenance --artifact dist/app.tar.gz --sbom reports/sbom.cdx.json \
  --provenance reports/provenance.json

# Build release evidence
sst evidence-bundle --release v2.9.0 \
  --include 'reports/**/*.json' \
  --include 'reports/**/*.md'
```

Aliases are also available for `release-assurance`, `exceptions`, and `org-model`.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
make doctor
make demo-product
make ui-server
```

Open `http://127.0.0.1:8080`.

## Quality and release validation

```bash
make test-fast
make test-integration-offline
make test-fuzz-smoke
make test-release
```

Use `make test-all` for the broader local suite. Fuzzing and workbench integration tests intentionally run subprocesses and can take substantially longer.

## Optional Snyk SBOM connector

The toolkit can pull SBOMs from Snyk projects and compare them with locally generated SBOMs. This is useful when you want to validate whether your existing Snyk project inventory agrees with the toolkit's repository intake/SBOM generation. The connector is dry-run-first and stores token references only.

```bash
make snyk-config SNYK_ORG_ID=<org-id> SNYK_PROJECT_ID=<project-id>
make snyk-test SNYK_ORG_ID=<org-id>
make snyk-pull-sbom SNYK_ORG_ID=<org-id> SNYK_PROJECT_ID=<project-id>

# Live API calls require the token env var and explicit SEND=1
export SNYK_TOKEN=...
make snyk-test SNYK_ORG_ID=<org-id> SEND=1
make snyk-pull-sbom SNYK_ORG_ID=<org-id> SNYK_PROJECT_ID=<project-id> SEND=1

# Compare the pulled Snyk SBOM to a locally generated SBOM
make snyk-compare SNYK_PULLED_SBOM=reports/snyk/snyk-project.sbom.cdx.json SNYK_LOCAL_SBOM=reports/repo-intake/sbom.cdx.json
```

The Workbench **Integrations** page includes Snyk configuration fields for org ID, project ID, token environment variable, SBOM format, and local SBOM comparison path.


## Quality and release gate

```bash
make test-fast
make test-integration-offline
make test-fuzz-smoke
make test-release
```

Use `make test-all` for the broader local suite. It can take longer because fuzzing workflows intentionally run subprocesses.

## Documentation

- `docs/ARCHITECTURE.md`
- `docs/deployment/INSTALL.md`
- `docs/demo/WALKTHROUGH.md`
- `docs/qa/RELEASE-GATE.md`
- `docs/product/FIRST-RUN.md`
- `ROADMAP.md`

---

## Full documentation and version history


**SBOM Security Toolkit** is a local-first, cloud-capable, source-available workbench for SBOM security operations, supplier SBOM intake, repository-to-SBOM analysis, release evidence, production integrations, and SBOM-focused fuzzing research.

It helps security teams, product-security engineers, AppSec teams, maintainers, and researchers answer practical questions:

- Is this SBOM valid, complete, useful, and ready for review?
- What is missing from a supplier SBOM before we can rely on it?
- Which vulnerabilities, unsupported dependencies, or VEX gaps need priority review?
- Do scanners agree on the same SBOM, or are there identity-matching differences?
- Can this build, supplier package, or repository pass a policy gate?
- Can malformed, ambiguous, or adversarial SBOMs cause crashes, timeouts, silent component drops, VEX loss, policy bypasses, or scanner disagreement?
- Can AI help generate fuzzing ideas and summarize evidence while keeping final security decisions human-controlled?
- Can the results be pushed into real workflows such as Jira, DefectDojo, Slack, GitHub PRs, SARIF, OpenVEX, CI/CD, and scheduled scans?

The project is intentionally **local-first**. The CLI, Make targets, and web workbench run on your machine by default. Uploaded SBOMs, repositories, logs, and generated evidence stay on disk unless you explicitly configure external integrations.

For teams, the toolkit is also **cloud-capable by choice**. Optional self-hosted mode adds Postgres/Redis/object-storage scaffolding, worker separation for long-running jobs, admin/RBAC scaffolding, scheduled scans, audit logs, notification targets, secret references, and deployment guidance while preserving safe defaults.

Current release: **v2.9.0 — Release Assurance and Governance**

---

## Why use this toolkit?

Most SBOM workflows are split across many tools: one tool generates SBOMs, another scans vulnerabilities, another stores results, another handles tickets, and fuzzing often lives in a completely separate research workflow. SBOM Security Toolkit sits above those pieces as an operations and evidence layer.

Use it when you want to:

- Validate supplier SBOMs before accepting them.
- Generate and compare SBOMs from repositories.
- Review unsupported, EOL, stale, deprecated, or abandoned dependencies with evidence-backed lifecycle signals.
- Run policy gates and release-decision checks.
- Produce evidence bundles for audits, vendor reviews, or release approvals.
- Fuzz SBOM parsers, scanners, and workflows for semantic failures.
- Use AI to suggest fuzz cases or summarize evidence without trusting AI to make decisions.
- Track project risk over time with deltas, trends, and evidence history.
- Run locally for sensitive analysis or self-host for team workflows.
- Export results to SARIF, OpenVEX, Jira, DefectDojo, GitHub PR summaries, Slack, webhooks, and email.

---

## What this toolkit does

SBOM Security Toolkit combines workflows that are often spread across several tools:

- **Repository intake:** build SBOMs from local repos, uploaded archives, or GitHub repos; detect ecosystems; compare SBOM generators; scan; fuzz generated SBOMs; check dependency health; and package evidence.
- **SBOM analysis:** explain, normalize, repair, diff, inventory, redact, score, and validate SBOMs.
- **Supplier intake:** minimum-elements checks, supplier-question generation, supplier reports, and reviewable evidence bundles.
- **Dependency health and lifecycle intelligence:** identify deprecated, abandoned, stale, unpinned, unsupported-risk, or EOL open source components from uploaded SBOMs or generated repository SBOMs, with optional endoflife.date-style product lifecycle lookups, registry metadata, confidence scoring, and offline cache support.
- **Policy and release evidence:** policy-as-code checks, release decision output, checksums/signing helpers, VEX helpers, Exploitability Decision Records, and evidence bundles.
- **Scanner operations:** scanner availability checks, scanner comparison, scanner confidence scoring, compatibility matrix, and curated scanner truth-set testing.
- **Project risk operations:** project workspaces, history recording, delta/trend reporting, release decision workflow, owner mapping templates, evidence viewer, and AI executive-summary scaffolding.
- **Local workbench UI:** upload SBOMs or repository archives, use local paths or GitHub URLs, launch workflows, view job status/logs, download evidence bundles, manage YAML-backed settings, run fuzzing workflows, and use Projects/Admin/Integrations pages.
- **Fuzzing lab:** structure-preserving mutation, schema-aware generation, semantic oracles, round-trip/metamorphic checks, scanner/toolchain fuzzing, stateful local Dependency-Track workflow fuzzing, replay packs, benchmarks, coverage scaffolding, ClusterFuzzLite scaffolding, and fuzz finding lifecycle tracking.
- **AI-assisted workflows:** prompt-only default mode, review queues, Claude Skills, provider-neutral agent prompts, GLM/local model profiles, Ollama/OpenAI-compatible hooks, Bedrock support, AI-assisted fuzzing triage/planning, and evidence-bound AI report writing for human-readable summaries.
- **Cloud-capable deployment:** optional self-hosted Docker Compose stack, cloud config helpers, cloud doctor, worker scaffold, S3-compatible evidence storage guidance, and AWS IAM/Secrets Manager/Bedrock notes.
- **Enterprise operations:** auth/RBAC scaffolding, users, service accounts, scheduled scan definitions, notifications, secret references, audit logs, API token generation, worker limits, and admin health checks.
- **Production integrations:** SARIF, OpenVEX, Jira, DefectDojo, GitHub PR summaries, CI/CD templates, notification delivery, scheduler runner, job lifecycle helpers, and evidence-retention cleanup.
- **Findings and remediation operations:** central finding lifecycle, deduplication, owners, SLA tracking, risk acceptance, suppression, fix verification, remediation plans, ticket text, campaigns, and next-best-action queues.

---


## AI Report Writer

v2.7.3 adds an evidence-bound AI report writer so users can generate human-readable reports and summaries instead of relying only on raw JSON, scanner output, SARIF, OpenVEX, lifecycle records, or evidence bundle contents.

Supported report types:

- Executive summary
- Engineering remediation report
- Supplier / vendor risk report
- Release decision memo
- Fuzzing summary report
- Lifecycle intelligence report
- Full security report

The report writer extracts facts from local evidence artifacts, writes the exact input fact bundle, writes the prompt used for review, and generates Markdown plus HTML output. AI providers are optional. In prompt-only mode, no network call is made. With Bedrock, Ollama, GLM, or OpenAI-compatible providers, AI drafts narrative text from the extracted facts.

AI remains advisory only. It does not approve releases, accept risk, suppress findings, mark findings fixed, or invent evidence.

```bash
make ai-report SBOM=test-sboms/example-spdx-2.3.json AI_REPORT_TYPE=full
make ai-report SBOM=./bom.json AI_REPORT_TYPE=executive AI_REPORT_AUDIENCE=executive
make ai-report SBOM=./bom.json AI_REPORT_PROVIDER=bedrock AI_REPORT_MODEL="$BEDROCK_MODEL_ID"
make ai-report-smoke

sst ai-report generate --sbom ./bom.json --report-type engineering --audience engineering
sst ai-report templates
```

Generated artifacts include:

```text
reports/ai/<report>.md
reports/ai/<report>.html
reports/ai/<report>.summary.json
reports/ai/<report>.prompt.md
reports/ai/report-input-facts.json
reports/ai/report-generation-metadata.json
```

The Workbench includes an **AI Reports** page for choosing audience, report type, tone, provider, model, SBOM path, project filter, and evidence roots. Generated reports are viewable from the Workbench **Reports** page.

## Lifecycle intelligence for unsupported/EOL components

v2.7.2 improves unsupported open source component detection by adding a lifecycle intelligence layer to dependency-health analysis. The toolkit now separates authoritative support signals from review heuristics:

- **EOL / unsupported:** SBOM metadata, maintainer/vendor lifecycle data, or an endoflife.date-style lifecycle source indicates support has ended.
- **Deprecated / abandoned:** registry or maintainer metadata marks a package deprecated or abandoned.
- **Possibly unmaintained / stale:** no observed release/update for the configured threshold; this is a review trigger, not automatic EOL.
- **Unknown:** no reliable lifecycle signal was found.

Network enrichment is opt-in. Offline mode uses SBOM metadata plus a tiny built-in smoke-test cache or a user-supplied lifecycle cache file.

```bash
make dependency-health SBOM=test-sboms/example-spdx-2.3.json
make lifecycle-intelligence SBOM=test-sboms/example-lifecycle.cdx.json OFFLINE_CACHE_ONLY=1
make dependency-health SBOM=./bom.json NETWORK=1 LIFECYCLE_SOURCES=sbom,known,registry,endoflife

sst lifecycle ./bom.json --network --lifecycle-sources sbom,known,registry,endoflife
```

Generated artifacts include:

```text
reports/dependency-health/dependency-health.json
reports/dependency-health/dependency-health.md
reports/dependency-health/dependency-health.csv
reports/dependency-health/lifecycle-intelligence.json
reports/dependency-health/lifecycle-intelligence.md
```

The Workbench upload and repository-intake forms now expose lifecycle source controls, optional lifecycle cache path, offline-cache-only mode, stale threshold, and network opt-in.

## What this is not

This project is **not** a replacement for mature production tools such as Syft, cdxgen, Trivy, Grype, OSV-Scanner, OWASP Dependency-Track, Snyk, FOSSA, Black Duck, Sonatype, Anchore, GUAC, SLSA tooling, OpenSSF Scorecard, Atheris, Jazzer, AFL++, or ClusterFuzzLite.

Instead, it is an **operations, testing, and experimentation layer** around those tools. It helps users validate, compare, explain, fuzz, triage, export, and package SBOM evidence in a repeatable workflow.

AI is advisory only. AI-generated seeds, harnesses, tests, summaries, and VEX/exploitability suggestions are staged for review. They are not executed, promoted, accepted, or trusted automatically unless you explicitly enable a validated deterministic workflow.

---

## Quick start

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
make setup
source .venv/bin/activate
make demo-full
make ui-server
```

Then open:

```text
http://127.0.0.1:8080
```

The packaged CLI is available as `sst` after setup:

```bash
sst version
sst analyze . --out-dir reports/latest
sst workbench --host 127.0.0.1 --port 8080
```

---

## Common workflows

### View reports in the Workbench

Use the **Reports** page to view generated reports directly in the Workbench instead of downloading the full evidence bundle every time. The page indexes reports from `reports/`, `release-evidence/`, `ui/storage/jobs/*/results`, `findings/`, `fuzzing/reports/`, and `projects/`.

```bash
make reports-index
sst reports index

# Preview a specific report by workspace-relative path
sst reports view reports/report-index.md
```

Supported previews include JSON, SARIF, Markdown, text, CSV, YAML, XML, and HTML-style artifacts. Evidence bundles remain available for archival/export, but day-to-day review can happen from the UI.


### Analyze a project or SBOM

```bash
make analyze PROJECT=./my-app
make sbom-score SBOM=./bom.json
make sbom-minimum-elements SBOM=./bom.json
make policy-check SBOM=./bom.json POLICY=policies/default-release-policy.yml
make report SBOM=./bom.json
```

### Repository intake

Analyze a local repository and generate an evidence bundle:

```bash
make repo-intake REPO_SOURCE=./my-app
```

Generate SBOMs only using the internal static fallback plus any installed generators:

```bash
make repo-sbom REPO_SOURCE=./my-app REPO_GENERATORS=auto
```

Analyze a private GitHub repository without putting the token in the command line or logs:

```bash
export GITHUB_TOKEN=github_pat_xxx
make repo-intake REPO_SOURCE=https://github.com/org/private-repo.git ALLOW_REMOTE=1 GITHUB_TOKEN_ENV=GITHUB_TOKEN
```

The Workbench also includes a **Repository Intake** tab for uploaded repository archives, local paths, and GitHub URLs. Pasted GitHub tokens are held only in process memory for the current job and are not written to status files, logs, or evidence bundles.

### Full all-actions scan

The main SBOM workflow dropdown includes:

```text
Full SBOM analysis + every action + all fuzzing scenarios
```

This mode runs the normal SBOM analysis pipeline, unsupported/out-of-date dependency analysis, scanner comparison, release-decision output, optional AI fuzz case generation, and broad timed fuzzing. The GUI exposes:

```text
Fuzz time per step/library
Fuzz targets: sbom,scanner,ai or all
Project ID
AI provider/model options
```

CLI equivalent:

```bash
TIME_BUDGET=60 LIBRARY_TARGETS=all make fuzz-all-timed SBOM=./bom.json
```

### Dependency health / unsupported dependency review

```bash
make dependency-health SBOM=./bom.json
make dependency-health SBOM=./bom.json NETWORK=1 STALE_DAYS=365
make repo-dependency-health REPO_SOURCE=./my-app
```

Unsupported detection is conservative. Explicit registry deprecation/abandonment metadata or SBOM EOL/support properties are treated as stronger evidence. Heuristics such as “no observed update for 365 days” are review triggers, not automatic proof that a package is unsupported.

### Review a supplier SBOM

```bash
make supplier-intake SBOM=./vendor-bom.json
make supplier-questions SBOM=./vendor-bom.json
make redact-sbom SBOM=./vendor-bom.json
```

### Generate release evidence

```bash
make release-evidence SBOM=./bom.json POLICY=policies/default-release-policy.yml
make release-decision SBOM=./bom.json
make checksums ARTIFACT_DIR=dist
make sign-artifacts ARTIFACT_DIR=dist
```

### Project risk tracking

```bash
make project-record PROJECT_ID=my-api SBOM=./bom.json RUN_DIR=reports/latest
make project-delta PROJECT_ID=my-api
make project-trend PROJECT_ID=my-api
make evidence-index EVIDENCE_DIR=reports/latest
make ai-executive-summary EVIDENCE_DIR=reports/latest
```

### Run local fuzzing workflows

```bash
make fuzz-all-local SBOM=test-sboms/clean/minimal-cyclonedx.json
TIME_BUDGET=60 make fuzz-all-timed SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-intelligence
make fuzz-corpus-recommend
make fuzz-vuln-matching
make fuzz-vex-logic
make fuzz-evil-supplier
make fuzz-lab-dashboard
```

### Use AI-assisted fuzzing safely

```bash
make ai-provider-test AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID"
make ai-provider-test AI_PROVIDER=glm AI_MODEL=glm-5.2
make ai-fuzz-analysis SBOM=./bom.json AI_PROVIDER=none AI_FUZZ_MODE=suggest
make ai-fuzz-analysis SBOM=./bom.json AI_PROVIDER=none AI_FUZZ_MODE=generate-run
make ai-fuzz-seeds AI_PROVIDER=none FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-harness-quality-loop TARGET=sbomops/minimum_elements.py AI_PROVIDER=none
make ai-seed-generator GOAL=vex-logic-errors AI_PROVIDER=none
make ai-fuzz-redteam AI_PROVIDER=none
```

`AI_PROVIDER=none` is prompt-only mode and requires no API key. Optional provider aliases include `bedrock`, `glm`, `ollama`, and `openai-compatible`.


### Findings and remediation operations

Import scan/SBOM findings into the central lifecycle store, dedupe across runs, assign owners, track SLA, generate remediation plans, and prove fixes with later evidence:

```bash
make findings-import SBOM=./bom.json FINDINGS_PROJECT=my-api FINDING_OWNER=platform-security
make findings-dashboard FINDINGS_PROJECT=my-api
make findings-sla FINDINGS_PROJECT=my-api
make findings-remediation FINDINGS_PROJECT=my-api
make findings-next-actions FINDINGS_PROJECT=my-api
make findings-export FINDINGS_PROJECT=my-api
```

Generate remediation ticket text for an individual finding:

```bash
make findings-ticket FINDING_ID=<finding-id> FIXED_VERSION=<safe-version>
```

Lifecycle operations are explicit and evidence-oriented:

```bash
make findings-assign FINDING_ID=<finding-id> FINDING_OWNER=payments-team
make findings-accept FINDING_ID=<finding-id> FINDING_REASON="Vendor fix unavailable; compensating controls applied" FINDING_EXPIRES_AT=2026-09-30
make findings-suppress FINDING_ID=<finding-id> FINDING_REASON="False positive confirmed by owner"
make findings-verify FINDINGS_PROJECT=my-api SBOM=./new-bom.json
```

The Workbench includes a **Findings** page for import, dashboards, SLA views, remediation plans, lifecycle actions, ticket templates, and fix verification.

Remediation plans include:

```text
root cause / finding source
recommended fix
upgrade or replacement guidance
breaking-change risk
risk to leave unfixed vs risk to fix
ecosystem-specific command suggestions
verification recipe
rollback guidance
compensating controls
acceptance criteria
```

AI may be used to summarize evidence or draft remediation language in adjacent workflows, but it does not approve exceptions, mark findings fixed, or make release-risk decisions.

### Production integrations

Dry-run is the default for live integrations. Live calls require explicit opt-in with `SEND=1` or `--send` plus environment-backed credentials.

```bash
make integration-smoke SBOM=test-sboms/example-spdx-2.3.json
make export-sarif SBOM=test-sboms/example-spdx-2.3.json
make export-openvex SBOM=test-sboms/example-spdx-2.3.json
make export-jira SBOM=test-sboms/example-spdx-2.3.json JIRA_PROJECT_KEY=SEC
make export-defectdojo SBOM=test-sboms/example-spdx-2.3.json
make github-pr-summary SARIF_OUT=reports/sarif/sbom-security-toolkit.sarif
make notify-test
```

Live Jira example:

```bash
export JIRA_BASE_URL="https://example.atlassian.net"
export JIRA_EMAIL="security@example.com"
export JIRA_API_TOKEN="..."
make jira-test SEND=1
make jira-create SBOM=test-sboms/example-spdx-2.3.json JIRA_PROJECT_KEY=SEC SEND=1
```

Live DefectDojo example:

```bash
export DEFECTDOJO_URL="https://defectdojo.example.com"
export DEFECTDOJO_TOKEN="..."
make defectdojo-test SEND=1
make defectdojo-upload SBOM=test-sboms/example-spdx-2.3.json SEND=1
```

---

## Workbench UI

Start the local UI:

```bash
make ui-server
```

The Workbench provides:

- SBOM upload and workflow launch
- Repository Intake
- Projects and project-risk history
- Settings for GUI-managed YAML configuration
- Admin page for enterprise scaffolding
- Integrations page for exports, CI templates, Jira/DefectDojo/notification dry runs, scheduler/job/evidence operations, and deployment scaffolds
- Fuzzing Lab workflow launch page
- time-limit controls for fuzzing runs
- run-all timed fuzzing workflow for user-defined seconds per step/library
- job status, logs, and evidence bundle downloads

Local mode binds to `127.0.0.1` by default. Treat it as a local single-user workbench unless you explicitly deploy the self-hosted cloud mode and configure authentication, network controls, and storage.

---

## GUI-managed configuration

The Settings page creates, validates, previews, imports, and exports the YAML files that power the CLI and UI. YAML remains the storage format so teams can keep GitOps workflows, code review, and repeatable automation, but users do not need to hand-edit files for common setup.

Managed configuration areas:

- **Policy Builder:** critical/high vulnerability gates, CISA KEV, exploit availability, unsupported dependencies, scanner disagreement, VEX contradiction, missing supplier/license/version, missing dependency graph, and stale dependency thresholds.
- **AI Provider Manager:** disabled/prompt-only, Bedrock, Ollama, GLM, and OpenAI-compatible provider definitions.
- **Fuzzing Profile Builder:** targets, per-target duration, seed count, AI mode, max AI cases, and whether validated generated cases should run.
- **Project Defaults:** default policy, AI provider, fuzzing profile, stale-days threshold, evidence retention, schedule label, and release-decision behavior.
- **Cloud Settings:** local/S3/MinIO storage selection, Postgres/local database mode, Redis/in-process queue mode, evidence retention, and worker enablement flags.

Generated files are written under:

```text
policies/generated/
configs/generated/ai-providers/
configs/generated/fuzzing-profiles/
configs/generated/project-defaults/
configs/generated/cloud/
```

CLI and Make helpers:

```bash
sst config list
sst config validate policies/generated/release-policy.yml
make config-policy CONFIG_NAME=release-policy STALE_DAYS=365
make config-ai-provider CONFIG_NAME=bedrock-default CONFIG_PROVIDER=bedrock CONFIG_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0
make config-fuzzing-profile CONFIG_NAME=release-smoke CONFIG_TARGETS=sbom,scanner,ai CONFIG_DURATION=60
make config-project-defaults CONFIG_PROJECT_ID=my-api
make config-cloud-settings CONFIG_NAME=self-hosted CONFIG_STORAGE_BACKEND=s3 CONFIG_S3_BUCKET=my-bucket
```

Secrets are intentionally not stored in generated YAML. Bedrock uses the AWS SDK credential chain or instance role; OpenAI-compatible providers should use environment variables or an external secret manager.

---

## Self-hosted cloud and enterprise mode

Local mode remains the default and safest way to run the toolkit. Cloud mode is opt-in and intended for self-hosted team deployments where you want shared project history, scheduled scans, retained evidence bundles, long-running fuzzing workers, admin controls, and external integrations.

Cloud helpers:

```bash
make cloud-config
make cloud-doctor
make cloud-schedule-template
make cloud-compose-up
make cloud-compose-down
make cloud-worker-smoke
```

Enterprise helpers:

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

Security model:

```text
Secrets are stored as references, not plaintext values.
Generated API tokens are shown once; only SHA-256 hashes are stored.
Passwords use PBKDF2-SHA256 hashes.
Audit logs are append-only JSON lines.
Live integrations are dry-run-first and require explicit send opt-in.
Full SaaS multi-tenancy and enforced OIDC login are future layers over the self-hosted foundation.
```

See:

- `docs/cloud/CLOUD-MODE.md`
- `docs/enterprise/ENTERPRISE-CLOUD-HARDENING.md`
- `docs/enterprise/OIDC-AND-WORKER-LIMITS.md`
- `docs/operations/SCHEDULER-JOBS-EVIDENCE.md`

---

## Fuzzing capabilities

The fuzzing lab focuses on **semantic SBOM failures**, not just crashes. It includes:

- SBOM-specific targets for CycloneDX, SPDX, purl, license expressions, VEX, and Dependency-Track payloads
- structure-preserving mutators and schema-aware seed generation
- grammar-mutator scaffolding for CycloneDX, SPDX tag-value, purl, license expressions, and VEX
- round-trip and metamorphic SBOM checks
- semantic oracles for component drops, dependency loss, duplicate identities, invalid references, and related issues
- scanner/toolchain fuzzing and metamorphic scanner checks
- vulnerability matching fuzzing for purl/CPE/ecosystem ambiguity
- VEX contradiction and logic fuzzing
- evil supplier SBOM scenarios for supplier-intake hardening
- fuzzing intelligence scoring and corpus promotion recommendations
- crash/replay packs, finding lifecycle tracking, and CI fuzzing scaffolding
- AI-assisted seed, campaign, harness, repair, red-team, and triage workflows
- format-tolerant handlers that normalize CycloneDX XML, SPDX, and tag-value inputs before JSON-oriented semantic fuzzing workflows

---

## How this compares to other tooling

| Category | Examples | Relationship to this toolkit |
|---|---|---|
| SBOM generators | Syft, cdxgen, Microsoft SBOM Tool, GitHub SBOM export | These generate SBOMs. This toolkit consumes, validates, scores, compares, repairs, and tests SBOM workflows. |
| Vulnerability scanners | Trivy, Grype, OSV-Scanner | These find known vulnerabilities. This toolkit wraps/compares scanner output and adds policy, confidence, fuzzing, and evidence workflows. |
| SBOM management platforms | Dependency-Track, Anchore, FOSSA, Black Duck, Snyk, Sonatype | These provide mature enterprise workflows. This toolkit is a lightweight local lab/workbench and reference implementation. |
| Supply-chain graph/provenance | GUAC, SLSA, OpenSSF Scorecard | These provide graph/provenance/posture context. This toolkit includes integration scaffolding and evidence workflows. |
| Fuzzing engines | Atheris, Jazzer.js, AFL++, ClusterFuzzLite | These provide fuzzing engines/infrastructure. This toolkit adds SBOM-specific inputs, mutators, semantic oracles, campaigns, and dashboards. |
| AI assistants | Claude Skills, GLM, Ollama, OpenAI-compatible endpoints, Bedrock | These can assist. This toolkit keeps AI optional, advisory, review-gated, and local-first by default. |

---

## Install, test, and package

```bash
make setup
make test
make validate
make preflight-release
make release VERSION=2.6.0
```

Docker helpers:

```bash
make docker-build
make docker-ui
make docker-dtrack
make docker-guac
```

---

## Data safety

This repository is designed to contain synthetic examples and local tooling only. Do not commit production SBOMs, customer data, secrets, internal package inventories, private vendor SBOMs, generated reports, or live tokens. Run this before releases:

```bash
make preflight-release
```

See `DATA-SAFETY.md` and `SECURITY.md`.

---

## Version history

#

## v2.7.3 — AI Report Writer

- Added evidence-bound AI report generation for executive summaries, engineering remediation reports, supplier risk reports, release decision memos, fuzzing summaries, lifecycle reports, and full security reports.
- Added fact extraction from SBOMs, findings, lifecycle intelligence, release evidence, fuzzing summaries, SARIF/OpenVEX, project history, and report artifacts.
- Added Markdown, HTML, JSON summary, prompt, metadata, and fact-bundle outputs under `reports/ai/`.
- Added prompt-only default mode plus optional Bedrock, Ollama, GLM, and OpenAI-compatible provider support.
- Added Workbench **AI Reports** page and integrated generated reports with the Workbench **Reports** viewer.
- Added `sst ai-report`, `sst ai-reports`, `make ai-report`, `make ai-report-facts`, `make ai-report-templates`, and `make ai-report-smoke`.
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

- Added a Workbench **Reports** page for browsing generated reports without downloading full evidence bundles.
- Added report indexing across job results, evidence outputs, project history, findings, fuzzing reports, and integration exports.
- Added JSON/SARIF/Markdown/text/CSV/YAML/XML/HTML preview support with safe workspace-relative path handling.
- Added `sst reports index`, `sst reports view`, `make reports-index`, and `make reports-view`.


Detailed release notes live in `CHANGELOG.md` and `RELEASE-NOTES.md`. This README keeps the evergreen introduction and usage guide first, then summarizes each major toolkit release below.


### v2.7.0 — Findings & Remediation Operations

Turns scan output into an operating workflow for remediation:

- Central findings store with normalized finding IDs, source, severity, owner, lifecycle state, evidence, ticket, and exception metadata.
- Deduplication across repeated scans with stable fingerprints.
- Lifecycle states for new, triaged, assigned, in progress, risk accepted, suppressed, candidate fixed, verified, and reopened.
- SLA tracking by severity/source with overdue and due-soon reporting.
- Time-bound risk acceptance and suppression records with owner, justification, expiry, and reopen conditions.
- Fix verification workflow that marks missing findings as candidate-fixed and then verified after review.
- Remediation plan generation with upgrade/replacement guidance, fix risk, verification steps, rollback notes, compensating controls, and acceptance criteria.
- Ticket-ready remediation templates.
- Owner routing from `owners.yml` by package/ecosystem.
- Campaigns and next-best-action queues for remediation operations.
- Workbench Findings page and CLI/Make targets.

See:

- `docs/remediation/FINDINGS-AND-REMEDIATION.md`

### v2.6.0 — Live Integrations + Operational Workflows

This release makes the production integration layer operational while keeping the project local-first and dry-run-first by default.

Highlights:

- Live Jira connection tests and issue creation with dry-run default and fingerprint-based deduplication.
- Live DefectDojo connection tests and upload workflow with dry-run default.
- Slack, webhook, and email notification delivery with explicit `--send`/`SEND=1` opt-in.
- GitHub PR summary and check-output generation from SARIF and release-decision artifacts.
- Real scheduler runner for enterprise schedule definitions, dry-run by default.
- Job lifecycle helpers for list, cancel, retry, rerun, and mark-reviewed workflows.
- Evidence retention cleanup with dry-run default.
- Offline integration smoke test harness for exporters, ticket payloads, and notification payloads.
- Workbench Integrations page updated with live/dry-run operation buttons.

See:

- `docs/integrations/LIVE-INTEGRATIONS.md`
- `docs/operations/SCHEDULER-JOBS-EVIDENCE.md`
- `docs/integrations/PRODUCTION-INTEGRATIONS.md`

### v2.5.0 — Production Integrations + Deployment Readiness

Adds production integration scaffolding and export formats:

- SARIF export for GitHub code scanning and compatible security tools.
- OpenVEX export for review-oriented VEX document generation.
- Jira and DefectDojo export scaffolds.
- CI/CD template generator for GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite, and Azure DevOps.
- GitHub App scaffold.
- Notification dry-run scaffolds for webhook, Slack, and email.
- Kubernetes/Helm deployment scaffold.
- OIDC configuration scaffold.
- Worker runtime limits.
- Enterprise demo data.
- Workbench Integrations page.

### v2.4.0 — Enterprise Cloud Hardening

Adds self-hosted team controls:

- Admin page and first-run setup wizard.
- Auth/RBAC scaffolding, users, roles, and service accounts.
- PBKDF2-SHA256 credential hashes and hash-only API token storage.
- Scheduled scan definitions.
- Notification target definitions.
- Secret reference manager for env vars, AWS Secrets Manager, Docker secrets, Kubernetes secrets, and local encrypted-file placeholders.
- Append-only JSONL audit log.
- Enterprise health/status checks.
- Enterprise CLI and Make helpers.

### v2.3.1 — GUI-Managed Configuration

Adds a Workbench Settings page so users can create, validate, preview, import, and export YAML configuration files that were previously path-only advanced inputs, including release policies, AI providers, fuzzing profiles, project defaults, and cloud settings.

### v2.3.0 — Project Risk Dashboard, All-Actions Scan, and Cloud-Capable Deployment

Turns one-off jobs into project-risk workflows:

- Local project workspaces.
- History recording.
- Delta and trend reports.
- Evidence-bundle viewer.
- Release decision workflow.
- GitHub Actions workflow generator.
- Policy tuning helper.
- Dependency owner template.
- AI executive-summary scaffold.
- Workbench dropdown option for “Full SBOM analysis + every action + all fuzzing scenarios.”
- Configurable fuzz time per step/library.
- Optional self-hosted cloud-mode scaffolding with Postgres, Redis, object storage, workers, and deployment guidance.

### v2.2.6 — AI-Enhanced Analysis and Bedrock Provider

Full SBOM Analysis can optionally generate AI-assisted fuzz case suggestions or run validated deterministic cases. The Fuzzing Lab and analysis UI include AWS Bedrock as a provider option.

### v2.2.5 — Structure-Preserving Fuzzing Stability

Fixes CycloneDX XML mutation failures when normalized component hash metadata is represented as a count and verifies the Workbench `test-all-components` flow passes the mutation step.

### v2.2.4 — Dependency Health UI Clarity

Makes unsupported/out-of-date dependency analysis explicit in Workbench workflow dropdowns for uploaded SBOMs and repository intake, including stale-threshold controls.

### v2.2.3 — Fuzzing Workflow Verification

Fixes the evil-supplier Make target, makes Docker-dependent language-engine fuzzing skip cleanly when Docker is unavailable, adds atomic Workbench status writes, and adds a full fuzz workflow smoke-test script.

### v2.2.2 — Fuzzing Observability

Every Fuzzing Lab job emits explicit run summaries and evidence bundles include final job state instead of stale running status.

### v2.2.1 — Dependency Health

Identifies deprecated, abandoned, stale, unpinned, or unsupported-risk open source dependencies from uploaded SBOMs or generated repository SBOMs, with optional registry enrichment and conservative stale-maintenance heuristics.

### v2.2.0 — Repository Intake

Build SBOMs from a local path, uploaded repo archive, or GitHub repository, including private GitHub repositories via a token; compare SBOM generators; run scanner workflows; fuzz the generated SBOM; and generate evidence from the resulting pipeline.

### v2.1.1 — Fuzzing UI Fixes

Restores per-run time limits, adds `fuzz-all-timed`, and normalizes CycloneDX XML and other supported non-JSON SBOMs before semantic fuzzing.

### v2.1.0 — Intelligent Fuzzing Operations

Adds fuzzing intelligence scoring, corpus promotion recommendations, harness quality auditing, AI harness quality loop, semantic format-diff fuzzing, vulnerability matching fuzzing, VEX logic fuzzing, evil supplier SBOM scenarios, AI red-team checks, CI fuzz dashboarding, and fuzz finding lifecycle tracking.

### v2.0.1 — Fuzzing Lab UI

Adds browser-accessible fuzzing workflow launch, fuzzing logs, upload-driven fuzzing jobs, configurable fuzzing options, and Fuzzing Lab result pages.

### v2.0.0 — Adaptive Fuzzing Platform

Adds fuzzing knowledge base, campaign planner, benchmark mode, scanner compatibility matrix, truth-set testing, replay packs, AI fuzz evaluation, ClusterFuzzLite scaffolding, and adaptive fuzzing workflows.

### v1.x — Core SBOM Intake, Evidence, Workbench, AI Fuzzing, and Packaging

The v1.x line introduced the original local-first SBOM intake and evidence workflows, local Workbench UI, AI-assisted fuzzing foundations, coverage-guided SBOM fuzzing, hardening/packaging helpers, and agent integrations.

---

## License

This project uses the **Functional Source License 1.1, Apache 2.0 Future License (`FSL-1.1-ALv2`)**. See `LICENSE`.

## Release assurance and governance (2.9)

Turn vulnerability, VEX, provenance, exception, and business-context evidence into a deterministic release decision:

```bash
sst assurance \
  --policy policies/production-release-assurance.yml \
  --findings reports/findings.json \
  --vex reports/vex.json \
  --exceptions governance/exceptions.yml \
  --provenance reports/provenance/provenance-verification.json \
  --context reports/context.json
```

See [Release Assurance](docs/RELEASE-ASSURANCE.md) for policy rules, exit codes, exception workflows, provenance verification, CI gates, and evidence bundles.

