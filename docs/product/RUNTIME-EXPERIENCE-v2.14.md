# Runtime Experience v2.14

## What changed

The guided user experience is now bound to the same job runner used by the advanced upload and repository workflows. Finishing Quick Start, submitting a Guided Workflow, or choosing “run initial analysis” during project creation queues a real job and redirects to live job status.

Every job automatically receives a **Full Security Engineering Report** after the scan reaches a terminal state. The report uses the existing evidence-bound AI report writer. When no provider is configured, the toolkit still produces the deterministic evidence report and prompt pack. A provider error is recorded as a reporting error and never changes the scan result.

The job page offers these additional versions without rerunning the scan:

- Executive
- Developer remediation
- Compliance and audit
- Supplier risk
- Customer-facing sanitized summary
- Release decision
- Fuzzing
- Lifecycle intelligence

## Live demo behavior

Demo mode is no longer a static dashboard. It creates an explicitly synthetic CycloneDX SBOM, queues the normal local analysis workflow, records subprocess status and logs, generates evidence artifacts, builds the download archive, and invokes automatic reporting. No credentials, network access, production data, or connector writes are required.

## Runtime safety

- Synthetic demo files are marked `synthetic: true`.
- External repository URLs still require the existing explicit remote-intake behavior.
- Reporting is advisory and evidence-bound.
- A failed report is retryable and non-blocking.
- Existing connector dry-run and read-only defaults are unchanged.

## Commands

```bash
make demo-live
make runtime-experience-smoke

make report-variant \
  JOB_DIR=ui/storage/jobs/<job-id> \
  REPORT_VARIANT=executive
```
