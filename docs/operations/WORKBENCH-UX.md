# Workbench User Experience

## Navigation model

The Workbench is organized around the operating workflow: Overview, Projects, Scans, Findings, Release Decisions, Action Center, Exceptions, Reports, Evidence, Connectors, Policies and Settings, Administration, and advanced analysis tools.

## Primary routes

| Route | Purpose |
|---|---|
| `/dashboard` | Posture, attention queue, recent scans, connector health |
| `/projects` | Project workspaces and trend views |
| `/jobs` | Scan history and execution details |
| `/findings` | Central finding and remediation lifecycle |
| `/decisions` | Release assurance outcomes |
| `/actions` | Work requiring attention |
| `/exceptions` | Exception approval and expiration visibility |
| `/integrations` | Connector catalog and configuration |
| `/reports` | Generated report inventory and previews |
| `/evidence` | Release and audit evidence inventory |
| `/search?q=...` | Global search |

## Design principles

- Essential decisions appear before raw scanner data.
- Empty states explain the next action.
- Advanced functionality remains available without dominating the main workflow.
- Live connector writes remain explicit and disabled by default.
- Existing local-first storage and operational behavior are preserved.
