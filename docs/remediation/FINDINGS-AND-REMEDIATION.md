# Findings and remediation operations

SBOM Security Toolkit v2.7 adds an evidence-backed remediation workflow around scan, policy, dependency-health, scanner, and fuzzing results.

## Goals

The remediation layer answers operational questions that raw scan output does not:

- What should we fix first?
- Who owns it?
- Is it overdue?
- Is the risk accepted or suppressed?
- What is the safest fix path?
- How do we verify it is actually fixed?
- Can we prove the decision with evidence?

## Finding lifecycle

Findings are stored under `findings/findings.json` and use stable fingerprints so repeated scans update existing records instead of creating duplicates.

Supported lifecycle states include:

```text
new
triaged
assigned
in_progress
risk_accepted
suppressed
candidate_fixed
verified
reopened
```

A finding that disappears from a later imported scan is marked `candidate_fixed`; it is not automatically considered fully remediated until verification records the fix.

## CLI and Make examples

```bash
make findings-import SBOM=./bom.json FINDINGS_PROJECT=my-api FINDING_OWNER=platform-security
make findings-dashboard FINDINGS_PROJECT=my-api
make findings-sla FINDINGS_PROJECT=my-api
make findings-remediation FINDINGS_PROJECT=my-api
make findings-next-actions FINDINGS_PROJECT=my-api
make findings-export FINDINGS_PROJECT=my-api
```

Assign or risk accept a finding:

```bash
make findings-assign FINDING_ID=<finding-id> FINDING_OWNER=payments-team
make findings-accept FINDING_ID=<finding-id> FINDING_REASON="Vendor fix unavailable; compensating controls applied" FINDING_EXPIRES_AT=2026-09-30
```

Generate a ticket-ready remediation template:

```bash
make findings-ticket FINDING_ID=<finding-id> FIXED_VERSION=<safe-version>
```

Verify fixes:

```bash
make findings-verify FINDINGS_PROJECT=my-api SBOM=./new-bom.json
```

## Remediation plans

Generated remediation plans include:

- affected component and version
- recommended target version or replacement guidance
- breaking-change risk
- risk to leave unfixed vs risk to fix
- ecosystem-specific command suggestions
- verification recipe
- rollback guidance
- compensating controls
- ticket acceptance criteria

The toolkit does not invent authoritative fixed versions. When a fixed version is not known from a scanner, vendor, or user-provided value, the remediation plan marks it as `unknown` and prompts review.

## Owner routing

Create an `owners.yml` file to route findings:

```yaml
owners:
  packages:
    npm:react: frontend-platform
    pypi:django: backend-platform
  ecosystems:
    maven: platform-engineering
```

## Exceptions and suppressions

Risk acceptance and suppression require explicit reason text. Risk acceptances should include an expiry date and reopen condition. The toolkit stores these with the finding record so release decisions and audit evidence can reference them.

## Workbench UI

The Workbench includes a **Findings** page for:

- importing SBOM findings
- viewing dashboards and SLA summaries
- generating remediation plans
- assigning owners
- applying risk acceptance or suppression
- generating ticket text
- verifying fixes
- exporting findings

## Safety model

AI may summarize remediation options or draft ticket language in adjacent workflows, but it should not approve exceptions, mark findings fixed, or decide release risk by itself. All remediation state changes are explicit user actions.
