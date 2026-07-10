# Continuous Fuzzing

This toolkit supports three fuzzing modes:

- `make fuzz-smoke` — short pull-request-safe fuzzing campaign.
- `make fuzz-nightly` — scheduled longer campaign.
- `make fuzz-deep` — manual long-running campaign for local or self-hosted runners.

The fuzzing subsystem focuses on SBOM-specific inputs as well as ecosystem-specific dependency parsers:

- CycloneDX JSON
- SPDX JSON
- package-url / purl strings
- SPDX-style license expressions
- common parser libraries discovered from SBOMs

Crash artifacts are normalized under `fuzzing/findings/<target>/` and may include:

- `crash-*` input
- `fuzz.log`
- `metadata.json`
- `reproducer.sh`

Use:

```bash
make fuzz-repro CRASH=fuzzing/findings/<target>/crash-...
make fuzz-scorecard
```

## Differential SBOM fuzzing

Differential runs compare how locally installed SBOM tools behave against the same input:

```bash
make fuzz-differential SBOM=vuln-scan/cyclonedx-sbom.xml
```

The harness records whether each available tool accepts, rejects, times out, or errors. Missing tools are reported as `missing`; the script does not install tools automatically.

## Corpus building

Build a seed corpus from a real SBOM:

```bash
make fuzz-corpus SBOM=vuln-scan/cyclonedx-sbom.xml
python3 fuzzing/tools/mutate-sbom.py vuln-scan/cyclonedx-sbom.xml
python3 fuzzing/tools/minimize-corpus.py fuzzing/generated-corpus --out fuzzing/minimized-corpus
```

## AI seed generation

AI-generated seeds must be reviewed before being committed or promoted into a corpus:

```bash
python3 fuzzing/tools/ai-seed-suggest.py --target "CycloneDX JSON" --count 10
```

The AI helper only writes candidate inputs. It does not execute generated code.
