# Advanced SBOM Fuzzing

The advanced fuzzing layer focuses on semantic SBOM failures, not just crashes. It adds structure-preserving mutation, semantic oracles, round-trip testing, metamorphic testing, campaign profiles, regression corpus handling, crash deduplication, and safe local API workflow fuzzing.

## Key commands

```bash
make fuzz-structured SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-roundtrip SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-metamorphic SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-oracles SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-campaign FUZZ_PROFILE=fuzzing/campaigns/sbom-parser-hardening.yml
make fuzz-regression
make fuzz-dedupe-crashes
make fuzz-coverage
make fuzz-malicious-metadata
```

## What this catches

Traditional fuzzing is good at finding crashes. SBOM tooling can also fail silently by dropping components, changing dependency relationships, rewriting package URLs, losing license data, or accepting invalid VEX/security metadata. The semantic oracle layer looks for those failures.

## Campaign profiles

Campaign profiles live in `fuzzing/campaigns/` and describe a repeatable fuzzing workflow. They are intentionally simple YAML files so teams can add project-specific profiles without changing code.

## Regression corpus

Promote interesting crashes or semantic failures into `fuzzing/regression/corpus/` and run:

```bash
make fuzz-regression
```

The regression corpus should stay small, reviewed, and safe to run on every pull request.

## Dependency-Track API fuzzing

`make fuzz-api` is dry-run by default. The API fuzzing scaffold refuses non-local targets and is intended only for local test containers you control.

## Future native engine work

The `fuzzing/proto/sbom_fuzz_model.proto` file is a scaffold for future libprotobuf-mutator/libFuzzer integration. The Python mutators provide the same structure-aware direction without requiring native tooling.
