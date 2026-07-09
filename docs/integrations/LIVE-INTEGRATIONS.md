# Live Integrations and Operational Workflows

v2.6.0 converts the v2.5 integration scaffolds into operational, dry-run-first workflows.

## Safety model

All live integrations default to dry-run behavior. Use `SEND=1` with Make or `--send` with the CLI only after testing configuration. Tokens are read from environment variables or secret references and are not written to reports.

## Jira

Dry-run payload generation and deduplication:

```bash
make jira-create SBOM=test-sboms/example-spdx-2.3.json JIRA_PROJECT_KEY=SEC
```

Live connection test:

```bash
export JIRA_BASE_URL="https://example.atlassian.net"
export JIRA_EMAIL="security@example.com"
export JIRA_API_TOKEN="..."
make jira-test SEND=1
```

Live issue creation:

```bash
make jira-create SBOM=test-sboms/example-spdx-2.3.json JIRA_PROJECT_KEY=SEC SEND=1
```

Created issue fingerprints are tracked in `reports/integrations/jira-state.json` to avoid duplicate issue creation.

## DefectDojo

Dry-run import payload:

```bash
make defectdojo-upload SBOM=test-sboms/example-spdx-2.3.json
```

Live upload test:

```bash
export DEFECTDOJO_URL="https://defectdojo.example.com"
export DEFECTDOJO_TOKEN="..."
make defectdojo-test SEND=1
make defectdojo-upload SBOM=test-sboms/example-spdx-2.3.json SEND=1
```

## Notifications

Notifications support webhook, Slack, and email. Dry-run is default:

```bash
make notify-test
```

Live send:

```bash
export SST_WEBHOOK_URL="https://hooks.slack.com/services/..."
python3 -m sbomops.integrations notify --type slack --target-ref SST_WEBHOOK_URL --send
```

## GitHub PR summary

Generate a PR comment body and check-result JSON from SARIF/release-decision output:

```bash
make github-pr-summary SARIF_OUT=reports/sarif/sbom-security-toolkit.sarif
```

## Offline smoke tests

```bash
make integration-smoke SBOM=test-sboms/example-spdx-2.3.json
```

This validates SARIF, OpenVEX, Jira dry-run, DefectDojo dry-run, and notification dry-run behavior without external network calls.
