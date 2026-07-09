# AI Report Writer

The AI Report Writer turns existing SBOM Security Toolkit evidence into readable Markdown/HTML reports for executives, engineers, security teams, suppliers, and audit/compliance stakeholders.

It is evidence-bound by design. The writer extracts local facts from SBOMs, findings, lifecycle intelligence, release decisions, fuzzing summaries, SARIF/OpenVEX, project history, and generated report artifacts. It writes the exact fact bundle and prompt used to generate the report.

AI is advisory only. It does not approve releases, accept risk, suppress findings, mark findings fixed, or create new findings.

## Report types

- `executive` — leadership summary, release posture, key risks, and next actions
- `engineering` — remediation-focused report with owners, fixes, verification steps, and tickets
- `supplier` — supplier/vendor SBOM assessment and follow-up guidance
- `release` — release decision memo with blockers, exceptions, residual risk, and evidence references
- `fuzzing` — fuzzing summary covering scenarios, crashes, scanner disagreements, and next tests
- `lifecycle` — unsupported/EOL/deprecated/stale dependency lifecycle report
- `full` — full security report across available evidence

## CLI usage

```bash
sst ai-report generate --sbom ./bom.json --report-type full --audience security
sst ai-report generate --sbom ./bom.json --report-type executive --audience executive --tone concise
sst ai-report generate --sbom ./bom.json --report-type engineering --audience engineering --project my-api
sst ai-report facts --sbom ./bom.json
sst ai-report templates
```

## Make targets

```bash
make ai-report SBOM=./bom.json AI_REPORT_TYPE=full
make ai-report SBOM=./bom.json AI_REPORT_TYPE=executive AI_REPORT_AUDIENCE=executive
make ai-report SBOM=./bom.json AI_REPORT_PROVIDER=bedrock AI_REPORT_MODEL="$BEDROCK_MODEL_ID"
make ai-report-facts SBOM=./bom.json
make ai-report-templates
make ai-report-smoke
```

## Providers

Default provider is `none`, which performs deterministic report generation and writes a prompt-only artifact for manual review. No network call is made.

Optional providers use the existing AI provider abstraction:

- `bedrock`
- `ollama`
- `glm`
- `openai-compatible`

Provider credentials are not stored by the report writer. Bedrock uses the AWS SDK credential chain. Local providers use their configured local endpoints/environment variables.

## Outputs

Reports are written under `reports/ai/` by default:

```text
reports/ai/<report>.md
reports/ai/<report>.html
reports/ai/<report>.summary.json
reports/ai/<report>.prompt.md
reports/ai/report-input-facts.json
reports/ai/report-generation-metadata.json
```

The Workbench **Reports** page can view generated report artifacts directly.

## Workbench usage

Open the Workbench and select **AI Reports**. Choose:

- report type
- audience
- tone
- AI provider
- model
- SBOM path
- project filter
- output directory
- optional evidence roots

After generation, use **Reports** to preview the Markdown, HTML, JSON summary, metadata, prompt, and extracted fact bundle.

## Safety model

The report writer follows these rules:

- It uses only extracted local facts.
- It writes the fact bundle and prompt for review.
- It states uncertainty when evidence is missing.
- It does not invent CVEs, fixed versions, due dates, or policy decisions.
- It does not approve releases.
- It does not accept risk.
- It does not suppress findings.
- It does not mark findings fixed.

Use AI reports as communication artifacts and review aids, not as authoritative governance decisions.
