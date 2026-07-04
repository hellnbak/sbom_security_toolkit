# SBOM Security Toolkit

**SBOM Security Toolkit** is a local-first, source-available workbench for SBOM security operations, supplier SBOM intake, release evidence, and SBOM-focused fuzzing research.

It is meant to help security teams, product-security engineers, AppSec teams, maintainers, and researchers answer practical questions:

- Is this SBOM valid, complete, and useful?
- What is missing from a supplier SBOM before we can rely on it?
- Which vulnerabilities need priority review, follow-up, or VEX/exploitability evidence?
- Do scanners agree on the same SBOM, or are there identity-matching differences?
- Can this build or supplier package pass a policy gate?
- Can malformed, ambiguous, or adversarial SBOMs cause crashes, timeouts, silent component drops, VEX loss, policy bypasses, or scanner disagreement?
- Can AI help generate fuzzing ideas and triage results without taking over security decisions?

The project is intentionally **local-first**. The CLI, Make targets, and web workbench run on your machine. Uploaded SBOMs and generated evidence stay on disk. Optional scanners, Dependency-Track, GUAC, ClusterFuzzLite, Claude Skills, GLM/local models, Ollama, or OpenAI-compatible providers can be enabled when you choose to use them.


## Current release: v2.1.1

This README reflects the current **v2.1.1** feature set. Since the v1.9 agent-integration release, the toolkit has added major v2.x capabilities:

- **v2.0.0 Adaptive Fuzzing Platform:** fuzzing knowledge base, campaign planner, benchmark mode, scanner compatibility matrix, truth-set testing, replay packs, AI fuzz evaluation, ClusterFuzzLite scaffolding, and adaptive fuzzing workflows.
- **v2.0.1 Fuzzing Lab UI:** browser-accessible fuzzing workflow launch, fuzzing logs, upload-driven fuzzing jobs, configurable fuzzing options, and Fuzzing Lab result pages.
- **v2.1.0 Intelligent Fuzzing Operations:** fuzzing intelligence scoring, corpus promotion recommendations, harness quality auditing, AI harness quality loop, semantic format-diff fuzzing, vulnerability matching fuzzing, VEX logic fuzzing, evil supplier SBOM scenarios, AI red-team checks, CI fuzz dashboarding, and fuzz finding lifecycle tracking.
- **v2.1.1 Fuzzing UI Fixes:** restored per-run time limits, added `fuzz-all-timed`, and fixed JSON-oriented fuzzing workflows so CycloneDX XML and other supported non-JSON SBOMs are normalized before semantic fuzzing.

The current focus is **local SBOM operations plus intelligent SBOM fuzzing**: upload or analyze SBOMs, generate decision-ready evidence, run scanner/toolchain comparisons, and exercise SBOM parsers/scanners with semantic fuzzing workflows from either the CLI or local web UI.

## What this toolkit does

SBOM Security Toolkit combines workflows that are often spread across several tools:

- **SBOM experience:** explain, normalize, repair, diff, inventory, redact, and score SBOMs.
- **Supplier intake:** minimum-elements checks, supplier-question generation, supplier reports, and evidence bundles.
- **Policy and evidence:** policy-as-code checks, release evidence, checksums/signing helpers, VEX helpers, and Exploitability Decision Records.
- **Scanner operations:** scanner availability checks, scanner comparison, scanner confidence scoring, compatibility matrix, and curated scanner truth-set testing.
- **Local workbench UI:** upload SBOMs, launch workflows, view job status/logs, download evidence bundles, and run fuzzing workflows from the browser.
- **Fuzzing lab:** structure-preserving mutation, schema-aware generation, semantic oracles, round-trip/metamorphic checks, scanner/toolchain fuzzing, stateful local Dependency-Track workflow fuzzing, replay packs, benchmarks, coverage scaffolding, ClusterFuzzLite scaffolding, and fuzz finding lifecycle tracking.
- **Intelligent fuzzing operations:** fuzzing intelligence scoring, corpus promotion recommendations, harness quality auditing, AI harness quality loop, AI seed-generator synthesis, grammar-mutator scaffolding, method-targeted coverage, semantic format-diff testing, vulnerability matching fuzzing, VEX logic fuzzing, evil supplier SBOM scenarios, AI red-team checks, CI fuzz result import, and local fuzzing dashboards.
- **AI-assisted workflows:** prompt-only default mode, review queues, Claude Skills, provider-neutral agent prompts, optional GLM/local model profiles, Ollama/OpenAI-compatible hooks, and AI-assisted fuzzing triage/planning.

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
make ai-provider-test AI_PROVIDER=glm AI_MODEL=glm-5.2
make ai-fuzz-seeds AI_PROVIDER=none FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-harness-quality-loop TARGET=sbomops/minimum_elements.py AI_PROVIDER=none
make ai-seed-generator GOAL=vex-logic-errors AI_PROVIDER=none
make ai-fuzz-redteam AI_PROVIDER=none
```

`AI_PROVIDER=none` is prompt-only mode and requires no API key. Optional provider aliases include `glm`, `ollama`, and `openai-compatible`.

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
make release VERSION=2.1.1
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
