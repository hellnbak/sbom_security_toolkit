# SBOM Security Toolkit Skill

Use this skill when the user is working with SBOM Security Toolkit or asks for help with SBOM intake, SBOM quality, supplier SBOM review, vulnerability prioritization, scanner disagreement, release evidence, fuzzing, AI-assisted fuzzing, or the local SBOM Workbench UI.

## What this skill helps with

This skill helps Claude guide users through SBOM Security Toolkit workflows. The toolkit is a local-first source-available workbench for validating SBOMs, scoring SBOM quality, reviewing supplier SBOMs, comparing scanner output, generating release evidence, fuzzing SBOM parsers/consumers, and staging AI-assisted fuzzing ideas for human review.

## Core safety principles

Always follow these principles:

1. AI suggests; deterministic tooling validates; humans approve.
2. Prefer local commands and local reports over sending SBOM content to external services.
3. Recommend redaction before sharing SBOM excerpts with an AI provider or third party.
4. Never decide that a vulnerability is `not_affected` without human-provided evidence.
5. Never auto-suppress, auto-close, or auto-accept vulnerability findings.
6. Never execute AI-generated code, fuzz harnesses, or scripts without explicit human review.
7. Treat supplier SBOMs, internal package names, repository URLs, and component inventories as potentially sensitive.
8. When unsure, produce a command plan and ask the user to run or approve it rather than inventing results.

## Prefer these commands

General setup and UI:

```bash
make setup
sst version
sst workbench --host 127.0.0.1 --port 8080
make ui-server
```

Analyze a project or SBOM:

```bash
sst analyze ./project --out-dir reports/latest
make analyze PROJECT=./project
make sbom-score SBOM=./bom.json
make sbom-minimum-elements SBOM=./bom.json
make policy-check SBOM=./bom.json POLICY=policies/default-release-policy.yml
make report SBOM=./bom.json
```

Supplier intake:

```bash
make supplier-intake SBOM=./vendor-bom.json
make supplier-questions SBOM=./vendor-bom.json
make redact-sbom SBOM=./vendor-bom.json
```

SBOM experience workflows:

```bash
make sbom-explain SBOM=./bom.json
make sbom-normalize SBOM=./bom.json
make sbom-repair SBOM=./bom.json
make sbom-inventory SBOM=./bom.json
make sbom-diff OLD_SBOM=./old.json NEW_SBOM=./new.json
```

Fuzzing workflows:

```bash
make fuzz-smoke
make fuzz-all-local
make fuzz-roundtrip SBOM=./bom.json
make fuzz-metamorphic SBOM=./bom.json
make fuzz-status
make fuzz-advisory CRASH=./fuzzing/crashes/example
```

AI-assisted fuzzing workflows:

```bash
make ai-fuzz-seeds FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-mutation-plan SBOM=./bom.json
make ai-crash-triage CRASH=./fuzzing/crashes/example
make ai-fuzz-campaign GOAL=sbom-parser-hardening
make ai-provider-test AI_PROVIDER=glm AI_MODEL=glm-5.2
make ai-review-list
```

Optional local-model mode can use the GLM provider profile. Use it only when the user has configured a local/OpenAI-compatible or Ollama-compatible endpoint, and keep output review-gated.

Release hardening:

```bash
make test
make validate
make preflight-release
make release VERSION=1.9.0
```

## Workflow guidance

### Supplier SBOM review

1. Start with `make redact-sbom` if the SBOM may contain sensitive names or URLs.
2. Run `make supplier-intake` and `make sbom-minimum-elements`.
3. Run `make supplier-questions` to draft vendor follow-up.
4. Run `make policy-check` if the organization has a policy profile.
5. Summarize gaps without overstating exploitability.

### Scanner disagreement

1. Run scanner comparison or inspect existing comparison output.
2. Look for identity mismatches such as purl versus CPE, missing ecosystem, missing version, or distro-specific matching.
3. Explain probable causes as hypotheses, not facts, unless report evidence supports them.
4. Recommend normalization, better purls, or supplier clarification.

### Fuzzing crash triage

1. Ask for or inspect the crash artifact, reproducer, logs, and minimized input.
2. Identify the failure type: crash, timeout, semantic mismatch, silent component drop, policy bypass, or scanner disagreement.
3. Recommend `make fuzz-dedupe-crashes`, `make fuzz-advisory`, and a regression test.
4. Do not claim a security vulnerability exists unless impact is clear and reproducible.

### AI-assisted fuzzing

1. Keep AI output in review queues.
2. Validate generated seeds with deterministic validators.
3. Do not auto-promote AI-generated corpus entries.
4. Do not auto-run AI-generated harnesses.
5. Prefer local model or prompt-only workflows for sensitive SBOMs.

## Report interpretation

When summarizing toolkit output, separate:

- observed facts from reports;
- inferred likely causes;
- recommended next actions;
- items requiring human review.

Use language like:

- “The report indicates...”
- “A likely cause is...”
- “This should be reviewed by...”
- “Do not mark this as not affected until...”

Avoid language like:

- “This vulnerability is definitely not exploitable”
- “You can safely ignore this”
- “The vendor is wrong”
- “The scanner is wrong”
