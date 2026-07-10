# v2.12.0

- Added Quick Start, project, and connector wizards, onboarding checklist, sample workspace, and Help Center.

# Changelog

## 2.12.0 — User Experience and GUI Coverage

- Replaced utility-centric Workbench navigation with a responsive workflow-oriented application shell.
- Added posture dashboard, project/scans/findings workflows, release decisions, action center, exception governance, connector health, reports, evidence inventory, and global search.
- Added Security Controls workspace for release assurance, OpenVEX drafting, provenance verification, evidence-bundle generation, organization context, and remediation planning.
- Added progressive disclosure, first-run and empty-state guidance, and narrow-screen support.
- Corrected release-assurance GUI input handling to use normalized findings.
- Added graceful HTTP 409 behavior when evidence bundles are not ready.
- Added GUI feature-coverage and route tests.
- Refreshed README, Quick Start, Roadmap, release notes, architecture, Workbench, GUI coverage, release-assurance, and validation documentation.
- Validated 66 tests in bounded groups.

## 2.10.0 — Connector Platform

- Added shared connector SDK, registry, capabilities, status artifacts, retries, pagination, and dry-run plans.
- Added first-class Snyk, Dependency-Track, DefectDojo, GitHub, and webhook connectors.
- Added unified connector CLI and Workbench connector health/configuration experience.
- Enforced read-only, environment-secret, TLS, and explicit-send safeguards.

## 2.9.0 — Release Assurance and Governance

- Added deterministic release decisions and stable CI exit codes.
- Added policy-as-code evaluation, expiring risk exceptions, compensating controls, VEX-aware decisions, provenance checks, organization context, and signed evidence helpers.
- Added GitHub and GitLab release-gate templates.

## Earlier releases

See `RELEASE-NOTES.md` for the detailed history of v2.8.x and earlier capabilities.
