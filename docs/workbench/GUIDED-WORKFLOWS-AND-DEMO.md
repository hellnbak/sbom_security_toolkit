# Guided Workflows and Demo

## Quick Start

Quick Start is a five-step wizard:

1. Choose the intended outcome.
2. Choose a repository or SBOM source.
3. Choose the environment.
4. Choose a policy or scan profile.
5. Start the task.

The final step calls the Workbench job runner, writes an execution contract, and redirects to the active job. It does not merely save onboarding state.

## Guided Workflows

Each workflow card maps to an executable job-runner workflow:

| Outcome | Executed workflow |
|---|---|
| Analyze an SBOM | `analyze` |
| Analyze a repository | `repo-analyze` |
| Review a release | `release-review` |
| Review supplier software | `supplier-intake` |
| Find unsupported dependencies | `dependency-health` |
| Fuzz SBOM tooling | `fuzz-all-timed` |
| Compare evidence | `scanner-compare` |

Repository source paths and GitHub URLs are passed to repository intake. Full or fuzz profiles enable repository fuzzing; quick and standard repository reviews do not force it.

## Execution contracts

Each guided job receives `execution-contract.json` describing the normalized workflow, planned steps, terminal-state requirement, automatic-report requirement, and non-blocking report behavior.

## Live demo

`make demo-live`:

1. Creates an explicitly synthetic CycloneDX SBOM.
2. Queues a `demo-live` job.
3. Borrows the normal analysis pipeline for deterministic local execution.
4. Writes synthetic demo findings and a demo manifest.
5. Generates the automatic engineering report.
6. Writes a demo-run summary.
7. Rebuilds the evidence archive.

The demo does not require credentials, network access, or production data. It is intended to demonstrate actual runtime behavior rather than static dashboard numbers.

## Job page

The job page displays:

- Current state and workflow label
- Execution options
- Step names, return codes, elapsed time, and blocking status
- Automatic report state and default report path
- Optional report-variant generation
- Result artifact links
- Logs
- Evidence download
