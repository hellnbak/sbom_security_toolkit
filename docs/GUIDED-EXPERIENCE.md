# Guided Experience

Version 2.12.0 adds goal-based onboarding so users can reach a security outcome without first learning the entire toolkit.

## Quick Start wizard

Open `/welcome` or select **Quick Start**. The wizard asks for a goal, source, environment, and policy preset, then records a safe starting configuration.

## Project wizard

Open `/project/new` to create project context with environment, criticality, exposure, ownership, classification, and default policy.

## Connector wizard

Open `/connectors/setup` to configure Snyk, GitHub, GitLab, Dependency-Track, DefectDojo, Jira, or a webhook. Connections are read-only and dry-run by default; secrets are referenced by environment variable.

## Sample workspace

Open `/sample` to explore a representative blocked release, findings, exception, and connector health state without credentials.

## Help Center

Open `/help` for plain-language guidance and direct links to common workflows.

## Safety

The guided UI does not store plaintext secrets, does not enable connector writes by default, and does not automatically modify source code.
