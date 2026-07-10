# SBOM Security Toolkit

SBOM Security Toolkit is a local-first, cloud-capable software supply-chain security workbench. It combines SBOM generation and intake, vulnerability and lifecycle analysis, release assurance, VEX, provenance, remediation, connector workflows, evidence packaging, reporting, and security-focused fuzzing in one CLI and web interface.

**Current release: v2.11.0 — User Experience and GUI Coverage**

## Highlights

- Guided Workbench with dashboard, projects, scans, findings, release decisions, action center, exceptions, connectors, reports, evidence, global search, and administration.
- Security Controls workspace for release assurance, VEX, provenance, organization context, evidence bundles, and remediation planning.
- Connector platform for Snyk, Dependency-Track, DefectDojo, GitHub, and generic webhooks, with dry-run and read-only defaults.
- SBOM support for CycloneDX and SPDX, repository intake, dependency health, lifecycle intelligence, policy checks, and supplier review.
- Evidence-bound AI reports and AI-assisted fuzzing with local/prompt-only operation available.
- Project history, normalized findings, risk exceptions, release gates, CI templates, signed evidence helpers, and cloud deployment scaffolding.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
pip install -e ".[dev]"

sst version
sst doctor
sst workbench
```

Open <http://127.0.0.1:8080/dashboard>.

## Workbench navigation

| Area | Purpose |
|---|---|
| Overview | Security posture, blocked releases, recent activity, and connector health |
| Projects | Project ownership, releases, risk, and history |
| Scans | Scan and repository-intake jobs |
| Findings | Normalized vulnerabilities, lifecycle issues, ownership, SLA, and remediation |
| Release Decisions | Pass, warning, approval-required, and blocked decisions |
| Action Center | Blocking issues, expiring exceptions, unhealthy connectors, and incomplete evidence |
| Exceptions | Risk acceptance, compensating controls, approvals, and expiration |
| Connectors | Configure, test, discover, and synchronize external tools |
| Reports | Engineering, executive, developer, compliance, supplier, and AI reports |
| Evidence | Release and audit evidence bundles |
| Security Controls | Release assurance, VEX, provenance, organization context, and remediation |

## Common CLI workflows

```bash
# Analyze an SBOM
sst analyze --help

# Intake a repository and create an SBOM/evidence set
sst repo-intake --help

# Evaluate a release decision
sst release-assurance --help

# Manage normalized findings and remediation
sst findings --help
sst remediation --help

# Create VEX, verify provenance, and package evidence
sst vex --help
sst provenance --help
sst evidence-bundle --help

# Configure and exercise connectors
cp configs/connectors.example.yml configs/connectors.yml
sst connectors list
sst connectors smoke

# Generate evidence-bound reports
sst ai-report --help
sst reports --help
```

## Safe defaults

- Local execution and local artifact storage by default.
- External network access requires explicit opt-in.
- Connectors are dry-run/read-only unless sending and writes are explicitly enabled.
- Tokens are referenced through environment variables rather than stored in configuration.
- AI output is advisory and cannot approve releases, accept risk, suppress findings, or invent evidence.
- Risk exceptions require scope, justification, owner/approver data, and expiration.

## Validation

The audited v2.11.0 package passed all 66 tests in bounded groups, including core, Workbench, connector, release-assurance, repository, cloud, AI-provider, packaging, and fuzzing modules. See [VALIDATION.md](VALIDATION.md) for scope and external-system limitations.

```bash
python3 -m compileall sbomops ai_fuzz fuzzing
pytest -q
```

Some legacy subprocess-heavy tests are best run in the bounded groups documented in `VALIDATION.md`.

## Documentation

- [Quick Start](QUICK_START.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Installation](docs/INSTALL.md)
- [Workbench UX](docs/operations/WORKBENCH-UX.md)
- [GUI Feature Coverage](docs/ui/GUI-FEATURE-COVERAGE.md)
- [Connector Platform](docs/CONNECTORS.md)
- [Release Assurance](docs/RELEASE-ASSURANCE.md)
- [Repository Intake](docs/repository/REPOSITORY-INTAKE.md)
- [Findings and Remediation](docs/remediation/FINDINGS-AND-REMEDIATION.md)
- [AI Report Writer](docs/reporting/AI-REPORT-WRITER.md)
- [Cloud Mode](docs/cloud/CLOUD-MODE.md)
- [Security](SECURITY.md)
- [Roadmap](ROADMAP.md)
- [Release Notes](RELEASE-NOTES.md)

## License

Functional Source License 1.1, Apache 2.0 Future License. See [LICENSE](LICENSE).
