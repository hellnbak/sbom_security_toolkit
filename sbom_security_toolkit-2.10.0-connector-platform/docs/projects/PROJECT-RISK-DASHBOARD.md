# Project Risk Dashboard

The v2.3 Project Risk Dashboard adds local project history on top of one-off SBOM jobs.

Use cases:

- Record recurring SBOM analysis runs for the same project.
- Compare the latest run against the previous run.
- View trend data for component count, missing versions, and SBOM quality estimates.
- Generate a release decision memo.
- Generate GitHub Actions workflow scaffolding.
- Generate a policy template and dependency-owner template.
- Build an evidence index for a local evidence bundle.

All project data is stored locally under `projects/`.

Example:

```bash
make project-init PROJECT_ID=my-api
make project-record PROJECT_ID=my-api SBOM=./bom.json RUN_DIR=reports/latest
make project-delta PROJECT_ID=my-api
make project-trend PROJECT_ID=my-api
make release-decision SBOM=./bom.json
```

The Workbench exposes a Projects page and a Project ID field on SBOM analysis jobs.
