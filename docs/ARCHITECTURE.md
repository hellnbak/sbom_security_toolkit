# Architecture

SBOM Security Toolkit is local-first and cloud-capable. The main layers are:

1. CLI and Make targets for reproducible workflows.
2. Workbench UI for uploads, jobs, reports, findings, AI reports, integrations, settings, and admin controls.
3. Analysis modules for SBOM quality, policy, dependency health, lifecycle intelligence, fuzzing, and reports.
4. Operational modules for projects, findings/remediation, integrations, scheduling, and evidence cleanup.
5. Optional self-hosted cloud components for API/UI, workers, Postgres, Redis, and object storage.

Safe defaults: local execution, network opt-in, AI opt-in, dry-run live integrations, and evidence-bound reporting.
