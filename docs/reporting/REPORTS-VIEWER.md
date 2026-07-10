# Workbench Reports Viewer

The Workbench Reports page lets users review generated reports without downloading an entire evidence bundle.

## What it indexes

The report index scans these local workspace locations:

- `reports/`
- `release-evidence/`
- `ui/storage/jobs/*/results/`
- `findings/`
- `fuzzing/reports/`
- `projects/`

Supported preview types include JSON, SARIF, Markdown, text, CSV, YAML, XML, and HTML-style artifacts.

## CLI usage

```bash
sst reports index
sst reports view reports/report-index.md
```

## Make usage

```bash
make reports-index
make reports-view REPORT_ID=reports/report-index.md
```

## Safety model

The report viewer only resolves workspace-relative paths inside the toolkit checkout. It does not expose arbitrary host files and it limits previews to a bounded number of bytes. Evidence bundles remain available for archival, sharing, or complete offline review.
