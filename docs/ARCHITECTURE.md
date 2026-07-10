# Architecture

SBOM Security Toolkit v2.11.0 is a local-first, cloud-capable software supply-chain security platform with six primary layers.

## 1. User interfaces

- `sst` CLI and Make targets for reproducible automation.
- FastAPI Workbench for guided local operation.
- CI templates for GitHub Actions and GitLab.

## 2. Workflow and control plane

- Projects, jobs, normalized findings, remediation, release decisions, exceptions, and evidence lifecycle.
- Security Controls workspace for release assurance, VEX, provenance, organization context, evidence generation, and remediation planning.
- Policy-as-code and stable release-decision exit codes.

## 3. Analysis services

- CycloneDX/SPDX normalization, quality scoring, minimum-elements checks, supplier intake, dependency health, lifecycle intelligence, vulnerability prioritization, scanner comparison, and SBOM repair.
- Coverage-guided, grammar, semantic, VEX-logic, and AI-assisted fuzzing.
- Evidence-bound deterministic and AI-assisted reporting.

## 4. Connector platform

- Shared connector registry and capability model.
- Snyk, Dependency-Track, DefectDojo, GitHub, and webhook adapters.
- Existing Jira, notifications, SARIF, OpenVEX, CI, and scheduled-integration helpers.
- Dry-run/read-only defaults, explicit network/write enablement, secret references, retries, and status artifacts.

## 5. Storage and evidence

Local filesystem storage is the default for projects, jobs, reports, connector state, findings, exceptions, and evidence bundles. Evidence packages can include checksums, manifests, policy decisions, SBOMs, VEX, reports, provenance, and optional signatures.

## 6. Optional cloud deployment

Self-hosted scaffolding supports API/UI services, workers, Postgres, Redis, object storage, OIDC, Kubernetes/Helm, and cloud AI providers. Cloud deployment is optional; the local Workbench remains fully supported.

## Trust boundaries and safe defaults

- Local execution and local storage by default.
- Network, AI, and connector writes require explicit opt-in.
- Secrets are referenced by environment variable or external secret store.
- AI output is advisory and evidence-bound.
- Release approval, risk acceptance, finding suppression, and code changes remain human-controlled.
