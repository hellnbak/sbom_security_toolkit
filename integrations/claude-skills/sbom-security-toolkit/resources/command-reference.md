# SBOM Security Toolkit Command Reference

## Setup

```bash
make setup
sst version
```

## Workbench UI

```bash
make ui-server
sst workbench --host 127.0.0.1 --port 8080
```

## Core analysis

```bash
make analyze PROJECT=./project
make sbom-score SBOM=./bom.json
make sbom-minimum-elements SBOM=./bom.json
make policy-check SBOM=./bom.json POLICY=policies/default-release-policy.yml
make report SBOM=./bom.json
```

## Supplier review

```bash
make supplier-intake SBOM=./vendor-bom.json
make supplier-questions SBOM=./vendor-bom.json
make redact-sbom SBOM=./vendor-bom.json
```

## SBOM experience

```bash
make sbom-explain SBOM=./bom.json
make sbom-normalize SBOM=./bom.json
make sbom-repair SBOM=./bom.json
make sbom-inventory SBOM=./bom.json
make sbom-diff OLD_SBOM=./old.json NEW_SBOM=./new.json
```

## Fuzzing

```bash
make fuzz-smoke
make fuzz-all-local
make fuzz-status
make fuzz-advisory CRASH=./path/to/crash
```

## AI-assisted fuzzing

```bash
make ai-fuzz-seeds FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-mutation-plan SBOM=./bom.json
make ai-crash-triage CRASH=./path/to/crash
make ai-fuzz-campaign GOAL=sbom-parser-hardening
make ai-provider-test AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID"
make ai-provider-test AI_PROVIDER=glm AI_MODEL=glm-5.2
make ai-review-list
```

## Release checks

```bash
make test
make validate
make preflight-release
make release VERSION=1.9.0
```
