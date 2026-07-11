# Roadmap

## Current release: v2.13.0 Actionable Workflows

The guided and actionable UX layer is complete. Future work should focus on multi-user persistence, production authentication/RBAC, real-time notifications, richer comparison charts, and browser automation tests.


# Roadmap

## Current release: v2.12.0 — User Experience and GUI Coverage

Delivered:

- Workflow-oriented Workbench navigation and posture dashboard.
- Project, scan, finding, decision, action, exception, connector, report, evidence, and search experiences.
- Security Controls workspace for release assurance, VEX, provenance, evidence, organization context, and remediation.
- Connector platform for Snyk, Dependency-Track, DefectDojo, GitHub, and webhooks.
- Audited GUI-to-backend coverage and bounded full-suite validation.

## Next: operational maturity

- Durable background connector synchronization with checkpoints and dead-letter queues.
- GitLab, AWS Security Hub, Microsoft Defender for Cloud, Google Security Command Center, ServiceNow VR, Splunk, Elastic, Sentinel, Slack, and Teams connectors.
- Bidirectional exception synchronization with conflict detection.
- Saved views, bulk actions, global command palette, and richer project workspaces.
- Stronger authentication, RBAC, audit trails, and multi-user deployment controls.
- OpenTelemetry metrics/traces and connector event envelopes.

## Later: enterprise and scale

- Worker isolation and horizontally scalable job execution.
- Hardened Kubernetes deployment and managed secret integrations.
- SSO/SAML/OIDC enforcement and tenant isolation.
- Runtime reachability and deployment-context correlation.
- Automated, human-approved remediation pull requests.
- Portfolio-level executive and auditor dashboards.
