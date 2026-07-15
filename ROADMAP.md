# Roadmap

Current release: **v2.14.2 — Reconciled Runtime and Documentation**

## Completed in v2.14.2

- One consistent source and documentation release.
- Automatic detailed report for every Workbench run.
- Report variants from the same evidence with archive refresh.
- Executable Quick Start and Guided Workflows.
- Real offline demo through the normal job runner.
- Release assurance, exceptions, provenance, release evidence, context, and connector reconciliation.
- Profile-controlled repository fuzzing.
- Tests for runtime contracts, release metadata, connectors, UX redaction, and release assurance.

## Near-term priorities

1. Convert the reconciled compatibility modules into richer adapter-specific implementations while preserving their current CLI contracts.
2. Add durable worker queues and process isolation for long-running repository and fuzzing jobs.
3. Add browser-based report comparison and run-over-run report deltas.
4. Add stronger JSON Schema validation at CLI and Workbench boundaries.
5. Expand release-assurance rules for EPSS, CVSS, KEV, reachability, direct/transitive status, finding age, fix availability, and environment.
6. Add signed evidence verification and policy enforcement in CI reference workflows.
7. Add migration tests across v2.8, v2.9, v2.10, v2.12, v2.13, and v2.14 configuration shapes.
8. Add accessibility and browser automation tests for all guided routes.

## Longer-term priorities

- Multi-user authenticated Workbench with production-grade RBAC and audit storage.
- Scalable worker deployment with Postgres, Redis, and object storage.
- Connector-specific discovery and import adapters for additional SBOM and vulnerability systems.
- Project-level dashboards combining current risk, trend, exceptions, ownership, and release posture.
- Pluggable policy packs for common regulatory and supplier-assurance use cases.
- Expanded corpus management, crash triage, replay, and continuous fuzzing operations.
- Signed release distributions and reproducible build metadata.
