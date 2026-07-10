# Connector Platform

SBOM Security Toolkit 2.10 introduces a shared connector registry and SDK for Snyk, Dependency-Track, DefectDojo, GitHub, and generic webhooks.

## Security defaults

Connectors are read-only by default. Network calls require `--send`. Write operations additionally require `read_only: false`. Tokens are referenced through environment variables and are never written to reports. TLS verification is enabled by default; disabling it is restricted to localhost test endpoints.

## Configure

```bash
cp configs/connectors.example.yml configs/connectors.yml
export SNYK_TOKEN='...'
export DEPENDENCY_TRACK_API_KEY='...'
export DEFECTDOJO_TOKEN='...'
export GITHUB_TOKEN='...'
```

Add or update a connector:

```bash
sst connectors add --name corporate-snyk --type snyk --config examples/connectors/snyk.yml
```

## Operate

```bash
sst connectors list
sst connectors test --name corporate-snyk
sst connectors test --name corporate-snyk --send
sst connectors discover --name corporate-snyk --send
sst connectors sync --name dependency-track --sbom reports/sbom.cdx.json
sst connectors sync --name dependency-track --sbom reports/sbom.cdx.json --send
```

The no-`--send` form generates a safe execution plan. Connector state is written under `reports/connectors/` for GUI display and audit history.

## Capabilities

| Connector | Project discovery | SBOM import/export | Findings | Exceptions | Remediation/notifications |
|---|---:|---:|---:|---:|---:|
| Snyk | Yes | Yes | Import | Import/export | No |
| Dependency-Track | Yes | Yes | Import/export | Import | No |
| DefectDojo | Yes | No | Import/export | Import/export | No |
| GitHub | Yes | SARIF path | Import/export | No | PRs and checks |
| Webhook | No | Metadata only | Export | No | Yes |

## Extending

Implement `Connector`, declare `Capabilities`, register the class in `CONNECTOR_TYPES`, and add offline tests. All connector implementations must support dry-run, retries, timeouts, idempotent state, secret references, and redacted output.
