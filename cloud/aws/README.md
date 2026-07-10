# AWS self-hosted mode notes

This folder contains starter AWS policy snippets for self-hosted cloud mode. Prefer instance/task roles, KMS-encrypted S3 buckets, Secrets Manager, and private subnets for workers.

Recommended AWS layout:

- ALB or private VPN access to the Workbench API/UI
- ECS/Fargate or EC2 for `sbom-workbench` and workers
- RDS Postgres for project/job history
- ElastiCache Redis for queueing
- S3 for evidence bundles and uploaded artifacts
- Secrets Manager for GitHub tokens and optional scanner/provider credentials
- Bedrock via IAM role when AI analysis is enabled

Do not run public internet exposure without authentication and TLS.
