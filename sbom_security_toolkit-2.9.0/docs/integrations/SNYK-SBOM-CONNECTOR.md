# Snyk SBOM Connector

The Snyk SBOM connector lets SBOM Security Toolkit import a Snyk project SBOM and compare it against a locally generated SBOM from repository intake or another SBOM generator.

This is complementary to GitHub/repository intake:

- **Repository intake** answers: what SBOM can this toolkit generate from the source or archive?
- **Snyk intake** answers: what SBOM/dependency view does the existing Snyk project expose?
- **Comparison** answers: where do the two SBOMs disagree on coverage, identity, or versions?

## Safety model

The connector is dry-run-first.

- The Workbench stores token references only, not raw Snyk tokens.
- CLI/Make live API calls require explicit `--send` or `SEND=1`.
- Dry-run mode writes planned request metadata and configuration files without contacting Snyk.
- Comparison reports are evidence for SBOM confidence and coverage drift, not vulnerability verdicts by themselves.

## Configuration

Recommended environment variables:

```bash
export SNYK_ORG_ID=<org-id>
export SNYK_PROJECT_ID=<project-id>
export SNYK_TOKEN=<token>
```

Generate connector config:

```bash
make snyk-config SNYK_ORG_ID=$SNYK_ORG_ID SNYK_PROJECT_ID=$SNYK_PROJECT_ID
```

Generated config is written to:

```text
configs/generated/integrations/snyk.yml
```

The config stores a token reference such as `env:SNYK_TOKEN`; it does not store the token value.

## Dry-run test

```bash
make snyk-test SNYK_ORG_ID=$SNYK_ORG_ID
```

Output:

```text
reports/snyk/snyk-test.json
```

## Live test

```bash
make snyk-test SNYK_ORG_ID=$SNYK_ORG_ID SEND=1
```

## Pull a Snyk project SBOM

Dry-run:

```bash
make snyk-pull-sbom SNYK_ORG_ID=$SNYK_ORG_ID SNYK_PROJECT_ID=$SNYK_PROJECT_ID
```

Live:

```bash
make snyk-pull-sbom SNYK_ORG_ID=$SNYK_ORG_ID SNYK_PROJECT_ID=$SNYK_PROJECT_ID SEND=1
```

Default output:

```text
reports/snyk/snyk-project.sbom.cdx.json
reports/snyk/snyk-pull-meta.json
```

Supported format values are passed through to the Snyk SBOM API request. Common choices:

```text
cyclonedx1.6+json
cyclonedx1.5+json
cyclonedx1.4+json
cyclonedx1.6+xml
spdx2.3+json
```

## Compare Snyk vs local SBOM

```bash
make snyk-compare \
  SNYK_PULLED_SBOM=reports/snyk/snyk-project.sbom.cdx.json \
  SNYK_LOCAL_SBOM=reports/repo-intake/sbom.cdx.json
```

Outputs:

```text
reports/snyk/snyk-sbom-compare.json
reports/snyk/snyk-sbom-compare.md
```

The comparison reports:

- Components only present in the Snyk SBOM
- Components only present in the local SBOM
- Version mismatches for shared component identities
- Recommendations for SBOM confidence review

## Workbench UI

Open the Workbench and go to **Integrations → Snyk SBOM connector**.

Configurable fields:

- Snyk organization ID
- Snyk project ID
- Token environment variable
- SBOM format
- Local SBOM path for comparison

The Workbench action performs safe configuration and dry-run checks. Use the CLI/Make targets with `SEND=1` for live API calls.

## Smoke test

```bash
make snyk-smoke
```

This creates deterministic sample SBOMs, writes a connector config, generates dry-run request metadata, and produces a comparison report.
