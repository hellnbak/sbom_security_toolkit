# SBOM Security Toolkit

SBOM Security Toolkit is a local-first, cloud-capable workbench for software supply-chain security. It combines SBOM generation and intake, quality checks, vulnerability and lifecycle analysis, release assurance, evidence packaging, remediation operations, integrations, and SBOM-focused fuzzing in one reviewable workflow.

Current release: **v2.14.2 — GitHub Reconciliation Hotfix**

## What changed in v2.14.2

This release retains the v2.14 automatic-reporting, executable-wizard, and live-demo work while repairing the packaging and GitHub update defects found in v2.14.1. It restores the complete v2.9-v2.13 repository capability surface and provides a non-destructive update process.

- Every Workbench run automatically produces a detailed, evidence-bound **Full Security Engineering Report**.
- Executive, developer, compliance, supplier, customer-facing, release, fuzzing, and lifecycle versions can be generated from the same completed run without rescanning.
- Quick Start, Guided Workflows, project creation, and Demo/QA launch actual background jobs instead of saving preferences or navigating to another form.
- Demo mode executes the normal local analysis pipeline against an explicitly synthetic CycloneDX SBOM and creates real logs, findings, reports, status transitions, and a downloadable evidence archive.
- Guided release review now runs deterministic release assurance in addition to the normal SBOM analysis pipeline.
- Guided repository scans use the selected repository source. Fuzzing is profile-controlled instead of being forced for every repository analysis.
- Added deterministic release assurance, governed risk exceptions, provenance verification, release evidence bundles, organizational context, and a dry-run-first unified connector interface.
- Added guided profiles, personas, saved views, activity history, notification preferences, policy simulation, redacted support bundles, and improved help pages.
- Fixed automatic-report lifecycle ordering, duplicate report generation, the `analyze-everything` lifecycle-cache command bug, and report-variant archive refresh.
- Replaced stale and duplicated release documentation with a single consistent v2.14.2 documentation set.
- Added legacy editable-install compatibility for macOS environments starting with pip 21.2.x.
- Restored repository-only CI, policy, schema, example, documentation, and regression-test files that the previous `rsync --delete` instructions could remove.
- Added a non-destructive release updater and corrected preflight handling for untracked demo artifacts.

See [Release Notes](RELEASE-NOTES.md), [Upgrade Guide](UPGRADE.md), and [Validation](VALIDATION.md).

## Quick start

```bash
git clone https://github.com/hellnbak/sbom_security_toolkit.git
cd sbom_security_toolkit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[dev]"
make doctor
make demo-live
make ui-server
```

Open `http://127.0.0.1:8080`.

The packaged CLI is installed as `sst`:

```bash
sst version
sst workbench --host 127.0.0.1 --port 8080
sst analyze . --out-dir reports/latest
```

## Workbench workflow

1. Open **Quick Start** or **Guided Workflows**.
2. Select an outcome, source, environment, and scan profile.
3. Start the workflow. A real job is queued and its execution contract is recorded.
4. Follow job status, steps, logs, and artifacts on the job page.
5. Review the automatically generated engineering report.
6. Generate other report versions from the same evidence when needed.
7. Download the refreshed evidence archive.

### Guided outcomes

- Analyze an SBOM
- Analyze a repository
- Review a release
- Review supplier software
- Find unsupported dependencies
- Fuzz SBOM tooling
- Compare scanner evidence

### Scan profiles

- **Quick:** fast local confidence checks
- **Standard:** normal local security review
- **Full:** broad analysis, dependency health, and configured fuzzing
- **Release:** release-focused analysis and assurance
- **Supplier:** supplier intake and follow-up evidence
- **Fuzz:** time-bounded fuzzing workflows

## Automatic reporting

The default report is generated after the deterministic job pipeline reaches a terminal state. Report generation is non-blocking: provider or narrative-generation errors are recorded but do not change the underlying scan result.

Default output:

```text
ui/storage/jobs/<job-id>/results/ai-reports/engineering/
  full-security-report.md
  full-security-report.html
  full-security-report.summary.json
  full-security-report.prompt.md
  report-input-facts.json
  report-generation-metadata.json
  automatic-report-status.json
```

Generate another version:

```bash
make report-variant \
  JOB_DIR=ui/storage/jobs/<job-id> \
  REPORT_VARIANT=executive
```

Supported variants: `executive`, `developer`, `compliance`, `supplier`, `customer`, `release`, `fuzzing`, and `lifecycle`.

See [Reporting](docs/reporting/AUTOMATIC-REPORTING.md).

## Working demo mode

`make demo-live` creates a synthetic SBOM, queues the normal Workbench job runner, executes real local analysis modules, generates the default report, and refreshes the evidence archive. It uses no production data, credentials, or network access.

```bash
make demo-live
make ui-server
```

Then open **Demo** or **Jobs** in the Workbench. See [Guided Workflows and Demo](docs/workbench/GUIDED-WORKFLOWS-AND-DEMO.md).

## Release assurance and governance

Evaluate findings with policy, VEX, approved exceptions, provenance, and organizational context:

```bash
sst assurance \
  --policy policies/production-release-policy.yml \
  --findings examples/release-assurance/findings.json \
  --vex examples/release-assurance/vex.json \
  --exceptions governance/exceptions.yml \
  --provenance examples/release-assurance/provenance-verification.json \
  --context examples/release-assurance/context.yml \
  --fail-on never
```

Possible decisions are `PASS`, `PASS_WITH_WARNINGS`, `APPROVAL_REQUIRED`, `BLOCK`, `INCOMPLETE_EVIDENCE`, and `ERROR`.

Create and approve a time-bound exception:

```bash
sst risk-exceptions create \
  --project demo-service \
  --vulnerability CVE-2026-DEMO-0001 \
  --justification "No compatible patched release is available" \
  --compensating-control "Service is not internet exposed" \
  --requestor security-team \
  --expires 2026-09-30

sst risk-exceptions approve <exception-id> --approver security-architecture
```

Verify provenance and build release evidence:

```bash
sst provenance --artifact dist/app.tar.gz --sbom reports/app.cdx.json \
  --provenance reports/provenance.json

sst evidence-bundle --release v2.14.2 \
  --include 'reports/**/*.json' \
  --include 'reports/**/*.md'
```

## Repository and SBOM analysis

```bash
# Analyze an SBOM
make sbom-score SBOM=./bom.json
make sbom-minimum-elements SBOM=./bom.json
make policy-check SBOM=./bom.json POLICY=policies/default-release-policy.yml
make dependency-health SBOM=./bom.json

# Analyze a local repository
make repo-intake REPO_SOURCE=./my-app

# Analyze a private GitHub repository without placing the token in arguments
export GITHUB_TOKEN=github_pat_xxx
make repo-intake \
  REPO_SOURCE=https://github.com/org/private-repo.git \
  ALLOW_REMOTE=1 \
  GITHUB_TOKEN_ENV=GITHUB_TOKEN
```

## Connectors and integrations

The unified connector interface stores environment-variable references rather than plaintext credentials and defaults to read-only or dry-run behavior.

```bash
cp configs/connectors.example.yml configs/connectors.yml
sst connectors list
sst connectors configure snyk-prod \
  --type snyk \
  --base-url https://api.snyk.io \
  --token-env SNYK_TOKEN \
  --mode read-only
sst connectors test snyk-prod
```

Existing integration modules remain available for Snyk, Dependency-Track, DefectDojo, Jira, Slack, webhooks, email, SARIF, OpenVEX, CI templates, and GitHub PR summaries. Live or write operations require explicit opt-in.

## Fuzzing

```bash
make fuzz-all-local SBOM=test-sboms/clean/minimal-cyclonedx.json
TIME_BUDGET=60 make fuzz-all-timed SBOM=test-sboms/clean/minimal-cyclonedx.json
make fuzz-vuln-matching
make fuzz-vex-logic
make fuzz-evil-supplier
make fuzz-lab-dashboard
```

AI-assisted fuzzing and reporting are advisory. Deterministic security decisions remain separate and human review remains required.

## Validation

```bash
make reconciled-test
make preflight-release
make demo-live
make preflight-release
```

For the broader project gates:

```bash
make test-fast
make test-integration-offline
make test-fuzz-smoke
make test-release
```

See [VALIDATION.md](VALIDATION.md) for the checks performed for this package and their limitations.

## Documentation

- [Quick Start](QUICK_START.md)
- [Upgrade Guide](UPGRADE.md)
- [GitHub Release Procedure](GITHUB-RELEASE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Automatic Reporting](docs/reporting/AUTOMATIC-REPORTING.md)
- [Guided Workflows and Demo](docs/workbench/GUIDED-WORKFLOWS-AND-DEMO.md)
- [Release Assurance and Governance](docs/RELEASE-ASSURANCE.md)
- [v2.14.2 Hotfix Notes](docs/releases/V2.14.2-HOTFIX.md)
- [Data Safety](DATA-SAFETY.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Roadmap](ROADMAP.md)

## Data safety

Do not commit production SBOMs, customer data, private package inventories, generated reports, live access tokens, or other sensitive evidence. Connector configuration should reference environment variables or a supported secret manager rather than storing secret values.

Run the release preflight before publishing:

```bash
make preflight-release
```

## License

This project uses the **Functional Source License 1.1, Apache 2.0 Future License (`FSL-1.1-ALv2`)**. See [LICENSE](LICENSE).
