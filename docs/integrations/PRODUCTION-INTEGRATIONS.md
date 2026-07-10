# Production Integrations

SBOM Security Toolkit v2.5 adds production-oriented integrations while preserving the local-first default.

## Exports

```bash
make export-sarif SBOM=path/to/sbom.cdx.json
make export-openvex SBOM=path/to/sbom.cdx.json VEX_STATUS=under_investigation
make export-jira SBOM=path/to/sbom.cdx.json JIRA_PROJECT_KEY=SEC
make export-defectdojo SBOM=path/to/sbom.cdx.json
```

SARIF is suitable for GitHub code scanning upload. Jira and DefectDojo exporters generate dry-run payloads by default and do not send data over the network. OpenVEX output is review-oriented and should be validated before external distribution.

## CI/CD templates

```bash
make ci-templates CI_PROVIDER=all
```

Generates starter templates for GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite, and Azure DevOps.

## GitHub App scaffold

```bash
make github-app-scaffold
```

Creates a configuration scaffold for a future GitHub App. Secrets are referenced by name and are not embedded.

## Notifications

```bash
make notify-test
python -m sbomops.integrations notify --type slack --target-ref SST_SLACK_WEBHOOK --send
```

Notifications are dry-run by default. Use `--send` only when the target reference resolves to an intended webhook or email destination.
