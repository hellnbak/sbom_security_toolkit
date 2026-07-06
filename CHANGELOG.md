# Changelog

## v2.2.5 - Structure-Preserving Fuzzing Stability

- Fixed structure-preserving SBOM mutation for normalized CycloneDX XML inputs whose component `hashes` field is represented as a count/integer.
- Improved `bom_ref` / `bom-ref` handling in the SBOM mutator.
- Verified the Workbench `test-all-components` debugging workflow passes the previously failing mutation step.


## v2.2.4 - Dependency Health UI Clarity

- Made unsupported/out-of-date dependency analysis easier to find in the local Workbench workflow dropdown.
- Added the same clarity to Repository Intake for dependency-health-only runs.
- Added stale-threshold controls to the uploaded SBOM workflow form.
- Updated README/release notes to reflect v2.2.4.


All notable user-facing changes are summarized here. This changelog is aligned with `README.md`, `RELEASE-NOTES.md`, `pyproject.toml`, `Makefile`, and `sbomops/__version__.py`.

## v2.2.3 - Fuzzing Workflow Verification and Workbench Stability

- Verified major Fuzzing Lab workflows against CycloneDX JSON and CycloneDX XML inputs.
- Added `scripts/smoke-fuzz-workflows.sh` and `make fuzz-workflow-smoke` for local regression coverage of fuzzing modes.
- Fixed `make fuzz-evil-supplier`, which used an obsolete argument.
- Made Docker-dependent fuzzing modes (`fuzz-python`, `fuzz-js`, `fuzz-php`, and `fuzz-smoke`) skip cleanly when Docker is unavailable.
- Fixed timed fuzzing variable propagation for `TIME_BUDGET` and `COUNT`.
- Changed workbench status writes to atomic replacement so the UI does not read partially written `status.json` files.

## v2.2.2 - Fuzzing Observability and Evidence Status

- Added `fuzz-run-summary.json` and `fuzz-run-summary.md` to every Fuzzing Lab job.
- Evidence bundles now include final completed/failed job status instead of stale `running` status.
- Metamorphic SBOM fuzzing now reports input stats, transform count, generated artifacts, and guidance explaining deterministic semantic checks versus timed all-mode fuzzing.
- CycloneDX XML inputs are normalized before JSON-oriented semantic fuzzing workflows.

## v2.2.1 - Dependency Health and Unsupported Dependency Review

- Added `dependency-health` workflow for uploaded SBOMs and repository-generated SBOMs.
- Added `repo-dependency-health` for repository intake pipelines.
- Added UI support for dependency-health checks, stale-day threshold configuration, and optional registry enrichment.
- Added optional enrichment for npm, PyPI, crates.io, and Packagist.
- Reports are generated as JSON, Markdown, and CSV.
- Uses conservative interpretation: stale release activity is a review trigger, not an automatic EOL conclusion.

## v2.2.0 - Repository Intake and SBOM Build Pipeline

- Added repository intake from local paths, uploaded archives, HTTPS GitHub URLs, and private GitHub repositories using a token.
- Added static ecosystem detection across common package managers and build systems.
- Added internal CycloneDX fallback generation plus orchestration for Syft, cdxgen, Trivy, Grype, and OSV-Scanner when installed.
- Added SBOM generator comparison, repository vulnerability scanning, optional fuzzing of generated SBOMs, and repository evidence bundles.
- Added Repository Intake tab in the local workbench UI.
- GitHub tokens are held only in process memory for the current job and are not written to logs, status files, reports, or evidence bundles.

## v2.1.1 - Fuzzing Lab Time Limits and Format-Tolerant Runs

- Restored browser controls for fuzzing time limits.
- Added `fuzz-all-timed` to run available fuzzing workflows for a user-defined time budget per step/library.
- Normalized supported non-JSON SBOMs, including CycloneDX XML, before JSON-oriented fuzzing workflows.

## Earlier releases

See `RELEASE-NOTES.md` for the full historical release narrative covering v1.x, v2.0.x, and v2.1.0.
