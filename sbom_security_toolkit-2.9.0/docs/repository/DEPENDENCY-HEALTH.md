# Dependency Health and Unsupported Dependency Review

SBOM Security Toolkit can analyze open source dependencies for support and maintenance risk. The goal is to identify components that deserve review, not to automatically declare every old package end-of-life.

## What it detects

The checker separates stronger evidence from heuristics.

Stronger signals:

- registry deprecation or abandoned-package metadata when available,
- SBOM properties that mark a component as deprecated, EOL, or unsupported,
- built-in project knowledge for a small set of known deprecated examples.

Heuristic signals:

- no observed release/update for the configured threshold, default `365` days,
- no exact version in the SBOM,
- range/unpinned versions that make support and vulnerability decisions unreliable.

A package with no updates for a year is **not automatically unsupported**. It is a review trigger. Stable libraries may not need frequent changes. Confirm support status from upstream maintainers, vendor statements, security policies, release notes, or project activity before making a final decision.

## CLI usage

```bash
make dependency-health SBOM=./bom.json
make dependency-health SBOM=./bom.json NETWORK=1 STALE_DAYS=365
```

Repository-generated SBOMs:

```bash
make repo-dependency-health REPO_SOURCE=./my-app
make repo-intake REPO_SOURCE=./my-app NETWORK=1
```

Direct CLI:

```bash
sst dependency-health ./bom.json --out-dir reports/dependency-health --stale-days 365
sst dependency-health ./bom.json --network
```

## Web UI

The Repository Intake tab includes a Dependency Health/EOL check option and a stale-day threshold. Network enrichment remains opt-in.

## Outputs

```text
reports/dependency-health/
  dependency-health.json
  dependency-health.md
  dependency-health.csv
```

Repository intake writes the same report under:

```text
reports/repo-intake/dependency-health/
```

## Supported optional registry enrichment

When `NETWORK=1` or `--network` is enabled, the lightweight checker can query public package metadata for:

- npm
- PyPI
- crates.io
- Packagist

The tool still works offline using SBOM metadata and heuristics.
