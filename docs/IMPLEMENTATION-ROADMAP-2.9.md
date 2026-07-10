# Integrated Roadmap Status

The 2.9 architecture establishes the common data and decision layer for all previously proposed features.

| Capability | 2.9 implementation |
|---|---|
| Policy-as-code | Unified YAML policy engine with stable decisions and exit codes |
| CI/CD gates | GitHub Actions and GitLab CI templates; generic CLI contract |
| Risk exceptions | Scoped, approved, expiring YAML store with audit history |
| VEX/reachability | VEX status consumption and reachability-aware policy rules |
| Provenance/signing | Digest-to-provenance validation and optional cosign verification |
| Continuous monitoring | Existing project history/diff retained; decisions are machine-readable for baseline comparison |
| Remediation PRs | Existing remediation workflows remain; decision JSON provides before/after gate evidence |
| Enterprise model | Organization → business unit → application → service → repository context |
| Integrations | Existing integration module remains the connector surface; policy-decision JSON is the normalized event |
| Evidence packages | Hash-manifested, optionally signed release bundles |
| Evidence-grounded AI | Reports consume deterministic decision artifacts rather than making acceptance decisions |

External systems remain opt-in. The toolkit does not silently create tickets, merge pull requests, accept risk, or publish evidence.
