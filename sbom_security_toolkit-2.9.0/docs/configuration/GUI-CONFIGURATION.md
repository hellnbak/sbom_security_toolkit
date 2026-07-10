# GUI-managed configuration

The Workbench Settings page lets users configure YAML-backed behavior without hand-editing YAML files. YAML remains the source of truth so configurations can still be reviewed, committed, imported, exported, and used from the CLI.

Managed configuration areas:

- Policy Builder: release/security gates and SBOM quality requirements.
- AI Provider Manager: prompt-only, Bedrock, Ollama, GLM, and OpenAI-compatible provider definitions.
- Fuzzing Profile Builder: targets, time budgets, seed counts, AI mode, and safe generated-case execution.
- Project Defaults: default policy, AI provider, fuzzing profile, stale threshold, retention, schedule label, and release-decision behavior.
- Cloud Settings: local/S3/MinIO storage, local/Postgres database mode, in-process/Redis queue mode, retention, and worker enablement.

Generated files are stored in:

```text
policies/generated/
configs/generated/ai-providers/
configs/generated/fuzzing-profiles/
configs/generated/project-defaults/
configs/generated/cloud/
```

Secrets are not stored in generated YAML. Use IAM roles, the AWS SDK credential chain, environment variables, or an external secret manager for provider and cloud credentials.

Useful CLI commands:

```bash
sst config list
sst config validate policies/generated/release-policy.yml
sst config policy --name release-policy --fail-on-critical --fail-on-cisa-kev --fail-on-unsupported
sst config ai-provider --name bedrock-default --provider bedrock --model '<model-id>' --region us-east-1
sst config fuzzing-profile --name release-smoke --targets sbom,scanner,ai --duration 60
sst config project-defaults --project-id my-api
sst config cloud-settings --name self-hosted --storage-backend s3 --s3-bucket my-evidence-bucket
```
