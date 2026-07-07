# AWS Bedrock AI Provider

SBOM Security Toolkit can optionally use AWS Bedrock as an AI provider for AI-assisted fuzzing workflows, including Full SBOM Analysis fuzz-case suggestions and the Fuzzing Lab.

Bedrock is optional. The toolkit still works in prompt-only mode without Bedrock, boto3, AWS credentials, or network access.

## Safety model

- Bedrock is never used unless selected/configured by the user.
- The toolkit does not store AWS access keys, session tokens, or Bedrock credentials.
- Credentials are resolved by the normal AWS SDK chain: EC2 instance role, environment variables, AWS profile, SSO, or other boto3-supported sources.
- SBOM excerpts are redacted before prompt construction where supported.
- AI output is advisory and review-gated.
- AI-generated fuzz cases are validated deterministically before execution.
- The toolkit does not automatically create VEX `not_affected` decisions or suppress vulnerabilities based on AI output.

## Environment setup

Install optional AWS SDK support if needed:

```bash
pip install boto3 botocore
```

Set a region and model ID:

```bash
export AWS_REGION=us-east-1
export BEDROCK_MODEL_ID='<your-bedrock-model-id>'
```

Then test the provider:

```bash
make ai-provider-test AI_PROVIDER=bedrock AI_MODEL="$BEDROCK_MODEL_ID"
```

or:

```bash
sst ai-provider-test --provider bedrock --model "$BEDROCK_MODEL_ID"
```

## Workbench usage

In the local web UI, choose **AWS Bedrock** as the AI provider from either:

- Full SBOM Analysis → optional AI-assisted fuzz cases
- Fuzzing Lab → AI provider

For EC2 deployments, using an instance role is preferred so no long-lived credentials are copied into the application environment.
