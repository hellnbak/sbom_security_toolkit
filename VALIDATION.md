# v2.10.0 Validation Report

Validation date: 2026-07-10

## Passed

- Python bytecode compilation for `sbomops`, `ai_fuzz`, and `fuzzing`.
- CLI version and connector command invocation.
- Unified connector offline smoke: 10/10 checks passed across Snyk, Dependency-Track, DefectDojo, GitHub, and webhook adapters.
- Legacy integration smoke: 6/6 checks passed.
- Static dashboard generation and connector-health rendering.
- Targeted connector, release-assurance, core, and packaging suite: 17 tests passed.
- Broader deterministic test selection displayed 41 passing tests.
- Individual AI-fuzz, Bedrock, and Claude provider test modules passed.

## Long-running suite limitation

`pytest -q` progressed without an observed assertion failure but did not terminate within 15 minutes. Isolation showed that the existing cloud/workbench and long-running fuzz workflow tests can block while waiting on subprocess/service behavior. The broader deterministic selection also printed all tests as passing but retained a live process after completion. These pre-existing integration-heavy workflows should be run in CI with per-test process timeouts and service fixtures.

No live third-party credentials were available, so external API writes were not executed. All connectors were validated end to end in offline/dry-run mode, including registry creation, capability reporting, guarded writes, status persistence, GUI rendering, and compatibility with existing integration exports.
