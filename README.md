# SBOM Security Toolkit

**SBOM Security Toolkit** is a local-first, cloud-capable, source-available workbench for SBOM security operations, supplier SBOM intake, release evidence, and SBOM-focused fuzzing research.

It is meant to help security teams, product-security engineers, AppSec teams, maintainers, and researchers answer practical questions:

- Is this SBOM valid, complete, and useful?
- What is missing from a supplier SBOM before we can rely on it?
- Which vulnerabilities need priority review, follow-up, or VEX/exploitability evidence?
- Do scanners agree on the same SBOM, or are there identity-matching differences?
- Can this build or supplier package pass a policy gate?
- Can malformed, ambiguous, or adversarial SBOMs cause crashes, timeouts, silent component drops, VEX loss, policy bypasses, or scanner disagreement?
- Can AI help generate fuzzing ideas and triage results without taking over security decisions?

The project is intentionally **local-first**. The CLI, Make targets, and web workbench run on your machine by default. Uploaded SBOMs and generated evidence stay on disk. For teams, the toolkit is now also **cloud-capable by choice**: optional self-hosted server mode adds Postgres/Redis/object-storage scaffolding, worker separation for long-running jobs, and cloud deployment guidance while preserving the same safety defaults. Optional scanners, Dependency-Track, GUAC, ClusterFuzzLite, Claude Skills, GLM/local models, Ollama, Bedrock, or OpenAI-compatible providers can be enabled when you choose to use them.


## Current release: v2.3.1

This README reflects the current **v2.3.1** feature set. Since the v1.9 agent-integration release, the toolkit has added major v2.x capabilities:

- **v2.0.0 Adaptive Fuzzing Platform:** fuzzing knowledge base, campaign planner, benchmark mode, scanner compatibility matrix, truth-set testing, replay packs, AI fuzz evaluation, ClusterFuzzLite scaffolding, and adaptive fuzzing workflows.
- **v2.0.1 Fuzzing Lab UI:** browser-accessible fuzzing workflow launch, fuzzing logs, upload-driven fuzzing jobs, configurable fuzzing options, and Fuzzing Lab result pages.
- **v2.1.0 Intelligent Fuzzing Operations:** fuzzing intelligence scoring, corpus promotion recommendations, harness quality auditing, AI harness quality loop, semantic format-diff fuzzing, vulnerability matching fuzzing, VEX logic fuzzing, evil supplier SBOM scenarios, AI red-team checks, CI fuzz dashboarding, and fuzz finding lifecycle tracking.
- **v2.1.1 Fuzzing UI Fixes:** restored per-run time limits, added `fuzz-all-timed`, and fixed JSON-oriented fuzzing workflows so CycloneDX XML and other supported non-JSON SBOMs are normalized before semantic fuzzing.
- **v2.2.0 Repository Intake:** build SBOMs from a local path, uploaded repo archive, or GitHub repository, including private GitHub repositories via a token; compare SBOM generators; run scanner workflows; fuzz the generated SBOM; and generate evidence from the resulting pipeline.
- **v2.2.1 Dependency Health:** identify deprecated, abandoned, stale, unpinned, or unsupported-risk open source dependencies from uploaded SBOMs or generated repository SBOMs, with optional registry enrichment and conservative stale-maintenance heuristics.
- **v2.2.2 Fuzzing Observability:** every Fuzzing Lab job now emits explicit run summaries and evidence bundles include final job state instead of stale running status.
- **v2.2.3 Fuzzing Workflow Verification:** fixes the evil-supplier Make target, makes Docker-dependent language-engine fuzzing skip cleanly when Docker is unavailable, adds atomic workbench status writes, and adds a full fuzz workflow smoke-test script.
- **v2.2.4 Dependency Health UI clarity:** makes unsupported/out-of-date dependency analysis explicit in the Workbench workflow dropdowns for both uploaded SBOMs and repository intake, including stale-threshold controls.
- **v2.2.5 Structure-preserving fuzzing stability:** fixes CycloneDX XML mutation failures when normalized component hash metadata is represented as a count, and verifies the Workbench test-all-components flow passes the mutation step.
- **v2.2.6 AI-enhanced analysis and Bedrock provider:** Full SBOM Analysis can optionally generate AI-assisted fuzz case suggestions or run validated deterministic cases; the Fuzzing Lab and analysis UI now include AWS Bedrock as a provider option.
- **v2.3.0 Project risk dashboard, full all-actions scan, and self-hosted cloud mode:** adds local project workspaces, history recording, delta/trend reporting, evidence-bundle viewer, release decision workflow, CI workflow generator, policy tuning helper, dependency owner template, AI executive-summary scaffold, a Workbench dropdown option for “Full SBOM analysis + every action + all fuzzing scenarios” with configurable fuzz time per step/library, and optional self-hosted cloud-mode scaffolding with Postgres, Redis, object storage, workers, and deployment guidance.
- **v2.3.1 GUI-managed configuration:** adds a Workbench Settings page so users can create, validate, preview, import, and export the YAML configuration files that were previously path-only advanced inputs, including release policies, AI providers, fuzzing profiles, project defaults, and cloud settings.

The current focus is **repository-to-SBOM operations, GUI-managed configuration, dependency health review, intelligent SBOM fuzzing, and project risk tracking**: upload or analyze SBOMs, point the toolkit at a repository, generate decision-ready evidence, run scanner/toolchain comparisons, exercise SBOM parsers/scanners with semantic fuzzing workflows, and optionally deploy the workbench in a self-hosted cloud mode for team usage and scheduled/background jobs.

**Documentation note:** this package consolidates the unpushed v2.2.0 through v2.3.1 changes into a single GitHub-ready tree. `README.md`, `CHANGELOG.md`, `RELEASE-NOTES.md`, `pyproject.toml`, `Makefile`, and `sbomops/__version__.py` are aligned to v2.3.1.


## v2.3.1 GUI-managed configuration

v2.3.1 turns YAML path fields into GUI-managed configuration. The Workbench now includes a **Settings** page for creating, validating, previewing, and importing the configuration files that power the CLI and UI. YAML remains the storage format so teams can keep GitOps workflows, code review, and repeatable automation, but users no longer need to hand-edit files for common setup.

The Settings page currently manages:

- **Policy Builder**: fail/warn rules for critical/high vulnerabilities, CISA KEV, exploit availability, unsupported dependencies, scanner disagreement, VEX contradiction, missing supplier/license/version, missing dependency graph, and stale dependency thresholds.
- **AI Provider Manager**: Disabled/prompt-only, Bedrock, Ollama, GLM, and OpenAI-compatible provider definitions with model, endpoint, region, default mode, max generated cases, and time budget. The GUI does not store API keys or AWS secrets.
- **Fuzzing Profile Builder**: targets, per-target duration, seed count, AI mode, max AI cases, and whether validated generated cases should run.
- **Project Defaults**: default policy, AI provider, fuzzing profile, stale-days threshold, evidence retention, schedule label, and release-decision behavior.
- **Cloud Settings**: local/S3/MinIO storage selection, Postgres/local database mode, Redis/in-process queue mode, evidence retention, and worker enablement flags.
- **YAML import/preview**: paste an existing YAML configuration into the GUI and save it into the generated configuration tree.

Generated files are written under:

```text
policies/generated/
configs/generated/ai-providers/
configs/generated/fuzzing-profiles/
configs/generated/project-defaults/
configs/generated/cloud/
```

CLI and Make helpers are also available:

```bash
sst config list
sst config validate policies/generated/release-policy.yml
make config-policy CONFIG_NAME=release-policy STALE_DAYS=365
make config-ai-provider CONFIG_NAME=bedrock-default CONFIG_PROVIDER=bedrock CONFIG_MODEL=anthropic.claude-3-5-sonnet-20240620-v1:0
make config-fuzzing-profile CONFIG_NAME=release-smoke CONFIG_TARGETS=sbom,scanner,ai CONFIG_DURATION=60
make config-project-defaults CONFIG_PROJECT_ID=my-api
make config-cloud-settings CONFIG_NAME=self-hosted CONFIG_STORAGE_BACKEND=s3 CONFIG_S3_BUCKET=my-bucket
```

Secrets are intentionally not stored in generated YAML. Bedrock uses the AWS SDK credential chain or instance role; OpenAI-compatible providers should use environment variables such as `OPENAI_API_KEY` or an external secret manager.

## v2.3.0 Project risk dashboard, all-actions scan, and cloud-capable deployment

v2.3.0 turns one-off analysis jobs into a lightweight project-risk workflow. The Workbench now has a **Projects** page, project IDs on scan jobs, local history recording, delta/trend helpers, release-decision output, a GitHub Actions workflow generator, policy tuning helper, dependency owner template, evidence viewer, and AI executive-summary scaffold. This package also adds optional **self-hosted cloud mode** scaffolding for teams that want Postgres-backed history, Redis-style queues, S3-compatible evidence storage, separated workers, and scheduled/background scans while keeping local mode as the default.

The main SBOM workflow dropdown also includes **Full SBOM analysis + every action + all fuzzing scenarios**. This mode runs the normal SBOM analysis pipeline, unsupported/out-of-date dependency analysis, scanner comparison, release-decision output, optional AI fuzz case generation, and broad timed fuzzing. The UI exposes a **Fuzz time per step/library** control and a **Fuzz targets** field such as `sbom,scanner,ai` or `all`.

The v2.3.0 validation refresh also adds a shared timed fuzzing runner (`scripts/run-timed-fuzz-suite.py`) used by both `make fuzz-all-timed` and the Workbench. The Fuzzing Lab includes a `test-all-components` debug workflow for exercising the core SBOM fuzzing components with the same input handling used by the UI.

```bash
make release-decision SBOM=./bom.json
make project-record PROJECT_ID=my-api SBOM=./bom.json RUN_DIR=reports/latest
make project-delta PROJECT_ID=my-api
make project-trend PROJECT_ID=my-api
make ci-generate
make policy-tune STALE_DAYS=365
make owners-template
make ai-executive-summary EVIDENCE_DIR=reports/latest
```


### Optional self-hosted cloud mode

Local mode remains the default and safest way to run the toolkit. Cloud mode is opt-in and intended for self-hosted team deployments where you want shared project history, scheduled scans, retained evidence bundles, and long-running fuzzing workers.

```bash
make cloud-config
make cloud-doctor
cp cloud/.env.example cloud/.env
# edit cloud/.env first
set -a; source cloud/.env; set +a
make cloud-compose-up
```

Cloud mode includes Docker Compose scaffolding for the Workbench API/UI, generic workers, fuzzing workers, Postgres, Redis, and MinIO/S3-compatible object storage. The toolkit does not require managed SaaS, and cloud mode should be deployed behind authentication, TLS, and a private network or reverse proxy. See `docs/cloud/CLOUD-MODE.md`.

## v2.2.6 AI-enhanced Full SBOM Analysis and Bedrock support

Full SBOM Analysis has an optional AI-assisted fuzzing phase. When enabled, the toolkit asks the configured AI provider for SBOM-specific fuzzing ideas, creates deterministic reviewable cases, validates them, and can run the safe generated cases. The default remains disabled/suggest-only so private SBOMs are not sent to external providers unless the user opts in.

The AI provider dropdown includes **AWS Bedrock** in both the main SBOM analysis form and the Fuzzing Lab. Bedrock uses the host AWS SDK credential chain, such as an EC2 instance role or AWS profile; the toolkit does not store AWS credentials in job status, logs, reports, or evidence bundles.

```bash
make ai-provider-test AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID"
make ai-fuzz-analysis SBOM=./bom.json AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID" AI_ANALYSIS_MODE=suggest
make ai-fuzz-analysis SBOM=./bom.json AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID" AI_ANALYSIS_MODE=generate-run
```

## v2.2.5 Structure-preserving fuzzing stability

The v2.2.5 patch specifically fixes a structure-preserving mutation bug found by the Workbench `test-all-components` debug workflow when a CycloneDX XML SBOM is normalized and component hash metadata appears as a count/integer instead of a list.


The Workbench now exposes unsupported/out-of-date dependency analysis more clearly in the workflow dropdowns:

- Uploaded SBOM workflow: **Unsupported / out-of-date dependency analysis**
- Repository Intake workflow: **Repository intake: unsupported / out-of-date dependency analysis**
- Stale-threshold controls are visible next to the relevant workflows.
- Network-enabled registry enrichment remains opt-in.

## v2.2.3 Fuzzing workflow verification fixes

This release verifies the Fuzzing Lab workflows end-to-end, fixes the `fuzz-evil-supplier` Make target, makes Docker-dependent language-engine fuzzing skip cleanly when Docker is unavailable, adds atomic workbench status writes to avoid partial `status.json` reads, and adds `make fuzz-workflow-smoke` for local regression checks across JSON and CycloneDX XML inputs.

## What this toolkit does

SBOM Security Toolkit combines workflows that are often spread across several tools:

- **Repository intake:** build SBOMs from local repos, uploaded archives, or GitHub repos; detect ecosystems; compare SBOM generators; scan; fuzz generated SBOMs; check dependency health/EOL risk; and package evidence.
- **SBOM experience:** explain, normalize, repair, diff, inventory, redact, score SBOMs, and analyze dependency support/maintenance health.
- **Supplier intake:** minimum-elements checks, supplier-question generation, supplier reports, and evidence bundles.
- **Policy and evidence:** policy-as-code checks, release evidence, checksums/signing helpers, VEX helpers, and Exploitability Decision Records.
- **Scanner operations:** scanner availability checks, scanner comparison, scanner confidence scoring, compatibility matrix, and curated scanner truth-set testing.
- **Local workbench UI:** upload SBOMs or repository archives, use local paths or GitHub URLs, launch workflows, view job status/logs, download evidence bundles, run fuzzing workflows from the browser, and use the Projects page for history/trends.
- **Project risk operations:** project workspaces, history recording, delta/trend reporting, release decision workflow, GitHub Actions generator, policy tuning, owner mapping template, evidence viewer, and AI executive-summary scaffold.
- **Cloud-capable deployment:** optional self-hosted Docker Compose stack, cloud config helpers, cloud doctor, scheduled-scan template, worker scaffold, S3-compatible evidence storage guidance, and AWS IAM/Secrets Manager/Bedrock notes.
- **Fuzzing lab:** structure-preserving mutation, schema-aware generation, semantic oracles, round-trip/metamorphic checks, scanner/toolchain fuzzing, stateful local Dependency-Track workflow fuzzing, replay packs, benchmarks, coverage scaffolding, ClusterFuzzLite scaffolding, and fuzz finding lifecycle tracking.
- **Intelligent fuzzing operations:** fuzzing intelligence scoring, corpus promotion recommendations, harness quality auditing, AI harness quality loop, AI seed-generator synthesis, grammar-mutator scaffolding, method-targeted coverage, semantic format-diff testing, vulnerability matching fuzzing, VEX logic fuzzing, evil supplier SBOM scenarios, AI red-team checks, CI fuzz result import, and local fuzzing dashboards.
- **AI-assisted workflows:** prompt-only default mode, review queues, Claude Skills, provider-neutral agent prompts, optional GLM/local model profiles, Ollama/OpenAI-compatible hooks, and AI-assisted fuzzing triage/planning.


## Repository intake quick start

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

The local web UI also includes a **Repository Intake** tab for uploaded repository archives, local paths, and GitHub URLs. Pasted GitHub tokens are held only in process memory for the current job and are not written to status files, logs, or evidence bundles.

## What this is not

This project is **not** a replacement for mature production tools such as Syft, cdxgen, Trivy, Grype, OSV-Scanner, OWASP Dependency-Track, Snyk, FOSSA, Black Duck, Sonatype, Anchore, GUAC, SLSA tooling, OpenSSF Scorecard, Atheris, Jazzer, AFL++, or ClusterFuzzLite.

Instead, it is an **operations, testing, and experimentation layer** around those tools. It helps users validate, compare, explain, fuzz, triage, and package SBOM evidence in a repeatable local workflow.

AI is advisory only. AI-generated seeds, harnesses, tests, and VEX/exploitability suggestions are staged for review. They are not executed, promoted, or trusted automatically.

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

## Common workflows

### Analyze a project or SBOM

```bash
make analyze PROJECT=./my-app
make sbom-score SBOM=./bom.json
make sbom-minimum-elements SBOM=./bom.json
make policy-check SBOM=./bom.json POLICY=policies/default-release-policy.yml
make report SBOM=./bom.json
```


### Dependency health / unsupported dependency review

Analyze an existing SBOM for deprecated, abandoned, stale, unpinned, or unsupported-risk dependencies:

```bash
make dependency-health SBOM=./bom.json
```

Enable optional registry enrichment for ecosystems currently supported by the lightweight checker, such as npm, PyPI, crates.io, and Packagist:

```bash
make dependency-health SBOM=./bom.json NETWORK=1 STALE_DAYS=365
```

Run dependency health as part of repository intake:

```bash
make repo-dependency-health REPO_SOURCE=./my-app
```

Unsupported detection is conservative. Explicit signals such as registry deprecation/abandonment metadata or SBOM EOL/support properties are treated as stronger evidence. Heuristics such as “no observed update for 365 days” are treated as review triggers, not automatic proof that a package is unsupported. Some mature libraries are stable and intentionally change rarely.

### Review a supplier SBOM

```bash
make supplier-intake SBOM=./vendor-bom.json
make supplier-questions SBOM=./vendor-bom.json
make redact-sbom SBOM=./vendor-bom.json
```

### Generate release evidence

```bash
make release-evidence SBOM=./bom.json POLICY=policies/default-release-policy.yml
make checksums ARTIFACT_DIR=dist
make sign-artifacts ARTIFACT_DIR=dist
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
make ai-fuzz-seeds AI_PROVIDER=none FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-harness-quality-loop TARGET=sbomops/minimum_elements.py AI_PROVIDER=none
make ai-seed-generator GOAL=vex-logic-errors AI_PROVIDER=none
make ai-fuzz-redteam AI_PROVIDER=none
```

`AI_PROVIDER=none` is prompt-only mode and requires no API key. Optional provider aliases include `bedrock`, `glm`, `ollama`, and `openai-compatible`.

## Local workbench UI

Start the local UI:

```bash
make ui-server
```

The workbench provides:

- SBOM upload and workflow launch
- job status and logs
- evidence bundle download
- scanner availability checks
- Fuzzing Lab workflow launch page
- time limit controls for fuzzing runs
- run-all timed fuzzing workflow for user-defined seconds per step/library
- Fuzzing Logs page
- Fuzzing Dashboard page for intelligence, corpus recommendations, AI red-team results, compatibility data, and finding lifecycle state

The UI binds to `127.0.0.1` by default. It has no auth, no database, and no cloud upload. Use it as a local single-user workbench.

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
- format-tolerant fuzzing handlers that normalize CycloneDX XML/SPDX/tag-value inputs before JSON-oriented semantic fuzzing workflows

## How this compares to other tooling

| Category | Examples | Relationship to this toolkit |
|---|---|---|
| SBOM generators | Syft, cdxgen, Microsoft SBOM Tool, GitHub SBOM export | These generate SBOMs. This toolkit consumes, validates, scores, compares, repairs, and tests SBOM workflows. |
| Vulnerability scanners | Trivy, Grype, OSV-Scanner | These find known vulnerabilities. This toolkit wraps/compares scanner output and adds policy, confidence, fuzzing, and evidence workflows. |
| SBOM management platforms | Dependency-Track, Anchore, FOSSA, Black Duck, Snyk, Sonatype | These provide mature enterprise workflows. This toolkit is a lightweight local lab/workbench and reference implementation. |
| Supply-chain graph/provenance | GUAC, SLSA, OpenSSF Scorecard | These provide graph/provenance/posture context. This toolkit includes integration scaffolding and evidence workflows. |
| Fuzzing engines | Atheris, Jazzer.js, AFL++, ClusterFuzzLite | These provide fuzzing engines/infrastructure. This toolkit adds SBOM-specific inputs, mutators, semantic oracles, campaigns, and dashboards. |
| AI assistants | Claude Skills, GLM, Ollama, OpenAI-compatible endpoints | These can assist. This toolkit keeps AI optional, advisory, review-gated, and local-first by default. |

## Install and packaging

```bash
make setup
make test
make validate
make preflight-release
make release VERSION=2.3.1
```

Docker helpers are available:

```bash
make docker-build
make docker-ui
make docker-dtrack
make docker-guac
```

## Data safety

This repository is designed to contain synthetic examples and local tooling only. Do not commit production SBOMs, customer data, secrets, internal package inventories, private vendor SBOMs, or generated reports. Run this before releases:

```bash
make preflight-release
```

See `DATA-SAFETY.md` and `SECURITY.md`.

## License

This project uses the **Functional Source License 1.1, Apache 2.0 Future License (`FSL-1.1-ALv2`)**. See `LICENSE`.
