# Changelog

## 2.14.2 — 2026-07-15

### Added

- Compatibility `setup.py` and a macOS virtual-environment bootstrap script.
- Non-destructive Git checkout updater with pre-application status and binary-diff backups.
- v2.14.2 hotfix documentation and regression coverage.
- Complete reconciled release tree combining the attached v2.8.2 package, verified later repository capability surface, and corrected v2.14 runtime work.
- Deterministic release assurance, risk exceptions, provenance verification, release evidence bundling, organization context, and unified connector commands.
- Release-review job-runner workflow.
- Guided scan profiles, outcomes, personas, saved views, activity, notifications, policy simulation, support, feedback, and help routes.
- Policies, examples, schemas, tests, reconciliation metadata, and current documentation.

### Changed

- `make reconciled-test` now runs the complete Python regression suite.
- Release preflight now evaluates tracked or manifested runtime files instead of rejecting harmless local demo output.
- CI validates Python 3.9 and 3.12 and installs the development extras.
- Automatic detailed engineering reporting now runs after deterministic job completion.
- Quick Start, Guided Workflows, project creation, and Demo/QA now execute tasks.
- Demo mode now runs the normal pipeline using synthetic evidence.
- Repository fuzzing is selected by profile or explicit fuzz workflow.
- Optional reports reuse the completed evidence and refresh the evidence archive.
- README, quick start, upgrade, release notes, architecture, roadmap, and validation documentation now use one consistent release version.

### Fixed

- Editable-install failure on Apple pip 21.2.4 caused by a missing legacy setuptools entry point.
- YAML files being passed to the JSON parser when PyYAML was unavailable.
- Destructive GitHub update instructions that could remove valid v2.9-v2.13 files.
- False preflight failure after running the live demo.
- Regression coverage gaps that allowed connector, release-assurance, and guided-UX compatibility issues into v2.14.1.
- `analyze-everything` lifecycle-cache `cmd`/`dep_cmd` bug.
- v2.14 overlay indentation incompatibility on the attached source tree.
- Missing Workbench route installation for guided pages.
- Duplicate automatic-report paths.
- Report variants missing from downloadable evidence archives.
- Undefined `PYTHON` Make variable that caused `demo-live` and runtime helper targets to execute `m ...` and ignore the failure.
- Stale v2.8/v2.12/v2.13 current-release declarations.

## 2.14.0

- Initial automatic-report, executable-wizard, and live-demo runtime work. Superseded by v2.14.2 because the overlay was not compatible with every older source tree.

## 2.13.0

- Actionable workflows and outcome-driven Workbench UX.

## 2.12.0

- Guided experience, profiles, personas, saved views, notifications, policy simulation, and support workflows.

## 2.11.0

- User-experience and documentation improvements.

## 2.10.0

- Connector platform and onboarding.

## 2.9.0

- Release assurance and governance.

## 2.8.x

- Productization, QA/demo readiness, Snyk SBOM connector, Quick Start/upload fixes, and automatic reporting foundations.

## 2.7.x and earlier

- Reports viewer, AI report writer, lifecycle intelligence, remediation operations, integrations, enterprise/cloud scaffolding, repository intake, and fuzzing platform foundations.
