# Architecture

## v2.14.2 runtime architecture

The Workbench is a local HTTP server backed by a filesystem job store. Guided UI routes translate user intent into a normalized workflow and call the same `create_job` entry point used by upload forms. Each job writes a status document, execution contract, logs, deterministic result artifacts, report state, and an evidence archive.

The runtime sequence is:

1. A route or CLI helper selects a workflow and source.
2. `sbomops.wizard_runtime` resolves policy/profile/source options.
3. `sbomops.workbench.job_runner.create_job` copies or references the input and starts the worker thread.
4. The job runner executes deterministic subprocess steps and writes their results.
5. `sbomops.workbench.runtime_hooks` starts automatic reporting after the workflow reaches a terminal state.
6. `sbomops.reporting_runtime` calls the evidence-bound report writer and records an independent report state.
7. The evidence ZIP is rebuilt after the default report and after each optional report variant.

The live demo uses this same path. Its only special behavior is synthetic evidence preparation and a demo summary around the normal analysis workflow.

Release assurance is deterministic and separate from AI narrative reporting. `sbomops.assurance` consumes policy, findings, VEX, exceptions, provenance, and context and emits a stable decision and exit code.

Connector configuration stores secret references and defaults to read-only or dry-run modes. Existing integration modules remain available for vendor-specific payloads and delivery.

---

SBOM Security Toolkit is local-first and cloud-capable. The main layers are:

1. CLI and Make targets for reproducible workflows.
2. Workbench UI for uploads, jobs, reports, findings, AI reports, integrations, settings, and admin controls.
3. Analysis modules for SBOM quality, policy, dependency health, lifecycle intelligence, fuzzing, and reports.
4. Operational modules for projects, findings/remediation, integrations, scheduling, and evidence cleanup.
5. Optional self-hosted cloud components for API/UI, workers, Postgres, Redis, and object storage.

Safe defaults: local execution, network opt-in, AI opt-in, dry-run live integrations, and evidence-bound reporting.