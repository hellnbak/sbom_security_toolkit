# Release Notes

## v2.12.0 — Guided Experience

This release makes the Workbench easier for new and occasional users while preserving advanced security-engineering workflows.

### Added

- Five-step Quick Start wizard based on user goals
- Guided source, environment, and policy selection
- Project creation wizard with ownership and business context
- Connector setup wizard with read-only and dry-run defaults
- Dashboard onboarding checklist and recommended actions
- Sample workspace requiring no credentials
- In-product Help Center
- Plain-language navigation and quick actions
- Responsive wizard and choice-card styling
- Documentation and regression coverage for all guided routes and forms

### Safety defaults

- Connector writes remain disabled unless explicitly enabled
- Secrets are referenced through environment variables and are not stored in plaintext
- Guided workflows create configuration and local artifacts; they do not merge code or approve risk automatically

### Upgrade

Upgrade from v2.11.0 by replacing the repository contents while preserving `.git`, then reinstalling with `pip install -e ".[dev]"`.

# Release Notes — v2.11.0

## SBOM Security Toolkit v2.11.0 — User Experience and GUI Coverage

This release turns the Workbench into a guided software supply-chain security application and completes GUI coverage for the major backend control-plane capabilities introduced in v2.9 and v2.10.

### Workflow-oriented Workbench

- Responsive sidebar and top action bar.
- Overview dashboard for posture, blocked releases, recent activity, and connector health.
- Project, scan, finding, release-decision, action-center, exception, connector, report, evidence, and search pages.
- Improved first-run, empty, loading, and error states.
- Mobile and narrow-screen behavior.
- Progressive disclosure for advanced technical details.

### Security Controls workspace

The new workspace provides GUI access to:

- release-assurance evaluation over normalized findings;
- OpenVEX draft generation;
- artifact and provenance digest verification;
- hash-manifested evidence-bundle generation;
- organization/ownership context templates; and
- deterministic remediation planning.

### Reliability corrections

- Corrected the GUI release-assurance form to match the backend normalized-findings contract.
- Added HTTP 409 handling when a job exists but its evidence bundle is not yet ready.
- Added live route tests for primary and advanced Workbench pages.
- Added an explicit GUI feature-coverage matrix.

### Compatibility

Existing CLI commands, policies, connector files, project records, findings, reports, and evidence directories remain compatible. External connector calls and writes remain opt-in.

### Validation

- Python compilation passed.
- All 66 tests passed in bounded deterministic groups.
- Coverage includes core SBOM operations, repository intake, dependency health, release assurance, connectors, Workbench routes, cloud mode, AI providers, packaging, and fuzzing modules.
- Connector offline smoke and legacy integration dry-run smoke passed.
- Live third-party writes were not performed because credentials were not supplied.

See `VALIDATION.md` for details.

## Upgrade

Apply the archive contents to the repository root, preserving `.git`, then reinstall:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
sst version
sst workbench
```

Open <http://127.0.0.1:8080/dashboard>.

## Previous major releases

### v2.10.0 — Connector Platform

Introduced the connector SDK and first-class Snyk, Dependency-Track, DefectDojo, GitHub, and webhook adapters, with safe defaults, status artifacts, retries, pagination, and unified CLI/GUI operations.

### v2.9.0 — Release Assurance and Governance

Introduced deterministic release decisions, policy-as-code gates, risk exceptions, VEX-aware evaluation, provenance checks, organization context, and signed evidence helpers.

### v2.8.x — Productization and Snyk integration

Added product QA/release workflows, demo readiness, GitHub project scaffolding, and the original Snyk SBOM connector.

For older feature history, consult Git tags and the repository changelog.
