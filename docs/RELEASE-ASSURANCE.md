# Release Assurance and Supply-Chain Governance

Version 2.9 introduces a deterministic control plane that turns scan evidence into an explicit release decision.

## Decision states

- `PASS` (exit 0)
- `PASS_WITH_WARNINGS` (exit 2)
- `APPROVAL_REQUIRED` (exit 3)
- `BLOCK` (exit 4)
- `INCOMPLETE_EVIDENCE` (exit 5)
- `ERROR` (exit 10)

## End-to-end flow

```bash
sst org-model context examples/org/enterprise.yml --repository customer-api --out reports/context.json
sst provenance --artifact dist/app.tar --sbom reports/sbom.cdx.json --provenance reports/slsa.json
sst assurance --policy policies/production-release-assurance.yml --findings reports/findings.json --vex reports/vex.json --exceptions governance/exceptions.yml --provenance reports/provenance/provenance-verification.json --context reports/context.json
sst evidence-bundle --release 2.11.0 --include 'reports/**/*.json' --include 'reports/**/*.md'
```

## Exceptions

Exceptions are explicit, scoped, expiring, and auditable. They do not remove findings; they convert a matched policy action into a warning while active.

```bash
sst exceptions create --project customer-api --vulnerability CVE-2026-12345 --rule critical-fix-available --justification 'Upgrade requires vendor release' --compensating-control 'WAF blocks vulnerable route' --requestor alice@example.com --expires 2026-08-31
sst exceptions approve RISK-... --approver security@example.com
```

## VEX and reachability

The assurance engine consumes CycloneDX/OpenVEX-like status statements. `not_affected`, `false_positive`, `resolved`, and `fixed` suppress policy matching for the exact vulnerability/component pair. Reachability can be supplied on normalized findings and used directly in policy.

## Provenance and signatures

`sst provenance` validates the artifact digest against a SLSA/in-toto subject and optionally invokes `cosign verify-blob` when cosign, a public key, and sidecar `.sig` files are available.

## Organization context

The organizational model enriches decisions with business unit, application, service, repository, criticality, exposure, ownership, data classification, and regulatory scope.

## Evidence bundles

`sst evidence-bundle` copies selected evidence, creates a hash manifest and checksum file, and can sign the manifest with keyless cosign where supported.
