# Workbench User Experience — v2.11.0

The Workbench is organized around the operating workflow rather than individual utilities.

## Start

```bash
sst workbench
```

Open <http://127.0.0.1:8080/dashboard>.

## Navigation model

Overview, Projects, Scans, Findings, Release Decisions, Action Center, Exceptions, Connectors, Reports, Evidence, Security Controls, Search, Settings, and Administration.

## Primary routes

| Route | Purpose |
|---|---|
| `/dashboard` | Posture, attention queue, recent scans, and connector health |
| `/projects` | Project ownership, history, releases, and trends |
| `/jobs` | Scan and repository-intake history |
| `/findings` | Normalized finding and remediation lifecycle |
| `/decisions` | Pass, warning, approval-required, and blocked decisions |
| `/actions` | Blocking work, expiring exceptions, connector failures, and incomplete evidence |
| `/exceptions` | Risk acceptance, approvals, controls, and expiration |
| `/integrations` | Connector catalog, configuration, testing, discovery, and sync |
| `/reports` | Generated report inventory and previews |
| `/evidence` | Release and audit evidence inventory |
| `/controls` | Release assurance, VEX, provenance, evidence, organization context, and remediation |
| `/search?q=...` | Global search |

## Design principles

- Decisions and next actions appear before raw scanner payloads.
- Empty and error states explain remediation steps.
- Advanced technical evidence remains available through progressive disclosure.
- External calls and writes remain explicit and disabled by default.
- Routes work on desktop and narrow-screen layouts.
- Existing CLI workflows remain the automation source of truth.

## Operational limitations

The v2.11.0 Workbench is intended primarily for trusted local or self-hosted use. Multi-user authentication, full RBAC enforcement, durable distributed jobs, and enterprise tenant isolation remain future hardening work.
