# Workflow Map

## Intake a supplier SBOM

1. `make redact-sbom SBOM=vendor.json` when sensitive data may be present.
2. `make supplier-intake SBOM=vendor.json`.
3. `make sbom-minimum-elements SBOM=vendor.json`.
4. `make supplier-questions SBOM=vendor.json`.
5. Summarize vendor follow-up items.

## Analyze a release

1. `make analyze PROJECT=./project` or use an existing SBOM.
2. `make sbom-score SBOM=bom.json`.
3. `make policy-check SBOM=bom.json POLICY=policies/default-release-policy.yml`.
4. `make report SBOM=bom.json`.
5. `make release-evidence SBOM=bom.json`.

## Triage fuzzing findings

1. `make fuzz-dedupe-crashes`.
2. `make ai-crash-triage CRASH=...` if AI assistance is desired.
3. `make fuzz-advisory CRASH=...` for a draft report.
4. Add a regression test only after review.

## Improve an SBOM

1. `make sbom-explain SBOM=bom.json`.
2. `make sbom-repair SBOM=bom.json`.
3. `make sbom-normalize SBOM=bom.json`.
4. Re-run scoring and policy checks.
