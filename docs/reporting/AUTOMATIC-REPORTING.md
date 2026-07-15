# Automatic Reporting

## Default behavior

Every Workbench job automatically attempts a detailed **Full Security Engineering Report** after the underlying workflow reaches a terminal state. The report consumes the completed job evidence and does not start another scan.

The scan result and report result are independent:

- A failed scanner or policy step remains visible in the job state.
- A report-provider failure is recorded as a non-blocking report error.
- A report error does not convert a completed scan into a failed scan.
- Prompt-only mode provides deterministic local report artifacts without a network request.

## Default artifacts

```text
results/ai-reports/engineering/
  full-security-report.md
  full-security-report.html
  full-security-report.summary.json
  full-security-report.prompt.md
  report-input-facts.json
  report-generation-metadata.json
  automatic-report-status.json
```

`results/ai-reports/report-options.json` records available variants and the reporting contract.

## Optional variants

- Executive Security Report
- Developer Remediation Report
- Compliance and Audit Evidence Report
- Supplier Risk Report
- Customer-Facing Security Summary
- Release Decision Memo
- Fuzzing Results Report
- Lifecycle Intelligence Report

Generate one from the job page or with:

```bash
python3 -m sbomops.reporting_runtime variant \
  --job-dir ui/storage/jobs/<job-id> \
  --type executive
```

The variant reuses the same fact bundle and evidence roots. After generation, the job's evidence ZIP is rebuilt so the new report is included.

## Providers

Prompt-only mode is the safe default. Existing report writer integrations can use Bedrock, Ollama, GLM, or OpenAI-compatible endpoints when explicitly configured. AI output remains advisory and cannot approve a release, accept risk, suppress findings, or mark remediation complete.

## Customer-facing variant

The customer-facing copy replaces detailed local evidence paths with an approved-disclosure statement and removes the workspace root. Review it before external distribution because the underlying evidence may still contain organization-specific facts.
