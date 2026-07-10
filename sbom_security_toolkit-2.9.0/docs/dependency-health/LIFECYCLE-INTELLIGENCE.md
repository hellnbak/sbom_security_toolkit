# Lifecycle Intelligence Sources

SBOM Security Toolkit v2.7.2 extends dependency-health analysis with lifecycle intelligence for unsupported and end-of-life components.

## Why this exists

Traditional dependency-health checks often confuse stale projects with unsupported projects. This feature separates explicit lifecycle evidence from heuristics.

## Supported signal types

- **SBOM metadata**: component properties such as `eol`, `endOfLife`, `supportStatus`, `sst:lifecycle_product`, and `sst:lifecycle_cycle`.
- **Known package metadata**: small built-in known-deprecated examples used only as review hints.
- **Registry metadata**: optional npm, PyPI, crates.io, and Packagist enrichment when `--network` is enabled.
- **endoflife.date-style lifecycle data**: optional product lifecycle lookup for runtimes, OS distributions, databases, frameworks, and platform components.
- **Offline cache**: user-provided JSON lifecycle cache for disconnected environments.

## Status model

The report intentionally separates statuses:

- `eol`: high-confidence lifecycle signal indicates the component cycle is past end-of-life.
- `deprecated_or_abandoned`: package metadata indicates deprecation or abandonment.
- `supported_until_eol_date`: lifecycle data exists and the EOL date has not passed yet.
- `very_stale_update_signal`: heuristic review signal; not automatic EOL.
- `stale_update_signal`: heuristic review signal; not automatic EOL.
- `version_unknown`: no exact version is available.
- `range_or_unpinned_version`: support decisions are unreliable until the version is resolved.
- `no_eol_signal_found`: no explicit unsupported/EOL signal was found.

## CLI examples

```bash
sst dependency-health ./bom.json --out-dir reports/dependency-health
sst lifecycle ./bom.json --network --lifecycle-sources sbom,known,registry,endoflife
sst lifecycle-intelligence ./bom.json --offline-cache-only --lifecycle-cache configs/lifecycle/eol-cache.json
```

## Make examples

```bash
make dependency-health SBOM=./bom.json
make lifecycle-intelligence SBOM=./bom.json OFFLINE_CACHE_ONLY=1
make dependency-health SBOM=./bom.json NETWORK=1 LIFECYCLE_SOURCES=sbom,known,registry,endoflife
```

## Offline cache format

```json
{
  "python": [
    {"cycle": "3.8", "eol": "2024-10-07", "latest": "3.8.20"}
  ],
  "nodejs": [
    {"cycle": "18", "eol": "2025-04-30", "latest": "18.20.8"}
  ]
}
```

## Workbench controls

The Workbench SBOM upload and repository-intake forms include:

- lifecycle source list
- optional lifecycle cache path
- offline-cache-only checkbox
- stale threshold
- network enrichment opt-in

## Safety notes

- Network access is opt-in.
- Stale update age is a review signal, not automatic EOL.
- A missing lifecycle signal does not prove support.
- High-confidence findings should still retain source evidence in generated reports.
