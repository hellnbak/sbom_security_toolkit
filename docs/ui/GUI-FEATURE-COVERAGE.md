# GUI Feature Coverage — v2.11.0

This matrix records where major backend capabilities are exposed in the Workbench.

| Capability | GUI location | Default behavior |
|---|---|---|
| SBOM upload and analysis | Scans / Upload | Local job |
| Repository intake | Scans / Repository Intake | Local; remote GitHub opt-in |
| Project history and trends | Projects | Read-only/project workflow |
| Normalized findings | Findings | Local lifecycle store |
| Remediation planning | Findings / Security Controls | Plan-only, human-reviewed |
| Release assurance | Release Decisions / Security Controls | Local deterministic evaluation |
| Risk exceptions | Exceptions | Local governance file with expiry |
| VEX | Security Controls / Connectors | Draft/export; no automatic risk acceptance |
| Provenance | Security Controls | Local digest and attestation inspection |
| Evidence bundles | Evidence / Security Controls / Job detail | Local generation and download |
| Organization context | Security Controls / Projects | Template/context generation |
| Connectors | Connectors | Read-only and dry-run by default |
| Reports and AI reports | Reports / AI Reports | Local generation; AI optional |
| Policies and settings | Settings | Local YAML/configuration management |
| Fuzzing and AI fuzzing | Advanced / Fuzzing | Time-bounded local jobs |
| Scanner compatibility | Advanced / Scanner Status | Read-only probe |
| Administration scaffolding | Administration | Local configuration |
| Global search | Search | Local indexes and documentation |

## Audit result

The v2.11.0 audit added missing GUI coverage for release assurance, VEX, provenance, evidence generation, organization context, and remediation. Live route smoke tests cover all primary routes. Evidence downloads return an explicit HTTP 409 response when a bundle is not yet ready instead of producing a server error.

## Not yet fully interactive

Some advanced capabilities expose plan, template, draft, or local verification workflows rather than live external writes. This is intentional: external writes, risk acceptance, release approval, and code modification remain explicit human-controlled actions.
