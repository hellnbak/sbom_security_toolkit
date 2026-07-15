# Release Notes

## v2.14.2 — GitHub Reconciliation Hotfix

v2.14.2 supersedes v2.14.1. It retains the automatic reporting, executable guided workflows, and live demo while correcting the installation, compatibility, preflight, and GitHub update defects discovered during a real macOS deployment.

### Packaging and upgrade hotfixes

- Adds a compatibility `setup.py` so editable installation works on macOS environments starting with pip 21.2.x.
- Documents upgrading pip, setuptools, and wheel inside the virtual environment before installing `.[dev]`.
- Adds `scripts/bootstrap-macos.sh` for a repeatable local installation.
- Adds `scripts/apply-release-safe.sh`, which records the existing Git diff and copies release files without deleting destination-only files.
- Removes the destructive `rsync --delete` update pattern.
- Restores valid v2.9-v2.13 CI, policy, schema, connector, example, guided-UX, and regression-test files.
- Changes release preflight to reject generated files only when they are tracked by Git or included in the release manifest.
- Adds ignored paths for demo state, local projects, generated configurations, and upgrade manifests.
- Produces a direct missing-PyYAML error instead of trying to parse YAML as JSON.
- Expands `make reconciled-test` to run the complete Python regression suite.


### Automatic reporting

- Generates a detailed Full Security Engineering Report for every Workbench run after the deterministic workflow reaches a terminal state.
- Keeps report status independent from scan status; report-provider failure does not change the scan result.
- Supports executive, developer, compliance, supplier, customer-facing, release, fuzzing, and lifecycle versions from the same run evidence.
- Refreshes the evidence archive after default and optional reports so downloadable evidence remains complete.
- Removes duplicate automatic-report execution paths.

### Executable guided experience

- Quick Start now queues a job on its final step.
- Guided Workflow cards map to concrete job-runner workflows.
- Project creation can immediately start the first analysis.
- Repository paths and URLs are passed to repository intake.
- Repository fuzzing is controlled by the selected profile instead of being forced by every repository analysis.
- Guided release review runs normal analysis plus deterministic release assurance.
- Every guided job receives an execution contract.

### Live demo

- Replaces static sample metrics with an offline synthetic CycloneDX run through the normal job runner.
- Produces real job states, steps, logs, findings, analysis artifacts, reports, demo metadata, and an evidence archive.
- Requires no production data, credentials, or network access.

### Release assurance and governance

- Adds deterministic decisions: `PASS`, `PASS_WITH_WARNINGS`, `APPROVAL_REQUIRED`, `BLOCK`, `INCOMPLETE_EVIDENCE`, and `ERROR`.
- Adds VEX-aware finding exclusion and approved, scoped, time-bound risk exceptions.
- Adds provenance subject/hash correlation and optional cosign verification.
- Adds release evidence manifests, checksums, archives, and optional signing.
- Adds organizational context and ownership validation.
- Adds policy, exception, connector, and release-decision schemas and examples.

### Connector and UX reconciliation

- Adds a unified connector interface with read-only/dry-run defaults and environment-variable secret references.
- Preserves existing vendor-specific integrations.
- Adds scan profiles, personas, saved views, activity history, notifications, policy simulation, feedback/help routes, and redacted support bundles.

### Runtime fixes

- Fixes the `analyze-everything` lifecycle-cache command variable.
- Fixes the v2.14 overlay indentation incompatibility on the attached v2.8.2 tree.
- Integrates missing guided routes into the actual Workbench server.
- Fixes optional report variants not appearing in the evidence archive.
- Defines the Makefile Python interpreter so demo and runtime helper targets execute instead of being treated as ignored `-m` recipes.
- Keeps report generation after deterministic evidence creation.

### Documentation

- Replaces contradictory README version declarations with one v2.14.2 declaration.
- Adds a clean quick start, upgrade guide, automatic-report guide, guided-workflow/demo guide, release-assurance guide, reconciliation notes, and validation record.
- Updates changelog, roadmap, version metadata, policies, examples, schemas, and release packaging guidance.

### Compatibility

Existing SBOM analysis, repository intake, supplier review, dependency health, lifecycle intelligence, Snyk workflows, findings/remediation, production integrations, project history, report viewing, fuzzing, and enterprise/cloud scaffolding remain available.

### Validation summary

- Python compilation passed.
- Targeted v2.14/v2.14.2 unit tests passed.
- Live demo completed using the normal job runner.
- Automatic engineering reporting completed.
- Executive and developer report variants were generated without rescanning.
- Variant reports were confirmed inside the refreshed evidence archive.
- Guided release review completed and produced deterministic release-assurance evidence.
- Workbench guided routes were exercised over HTTP.

See `VALIDATION.md` for exact commands and limitations.

---

## Previous major releases

- **v2.13.0 — Actionable Workflows:** guided outcome selection, workflow previews, project setup, connector onboarding, sample workspace, and improved job details.
- **v2.12.0 — Guided Experience:** first-run wizard, scan profiles, policy simulator, personas, saved views, notifications, activity history, support bundle, and help/feedback experience.
- **v2.11.0 — User Experience:** navigation, onboarding, result presentation, and documentation improvements.
- **v2.10.0 — Connector Platform:** normalized connector configuration, discovery/sync contracts, and dry-run-first onboarding.
- **v2.9.0 — Release Assurance and Governance:** release decisions, risk exceptions, VEX/reachability, provenance, release evidence, and organizational context.
- **v2.8.x — Productization and Automatic Reports:** QA tiers, demo/productization helpers, Snyk connector, upload UX, and automatic reporting foundations.
- **v2.7.x — Reports, Lifecycle, and Remediation:** report viewer, lifecycle intelligence, AI report writer, and findings/remediation operations.
- **v2.6 and earlier:** live integrations, cloud/enterprise scaffolding, project operations, repository intake, and the SBOM fuzzing platform.
