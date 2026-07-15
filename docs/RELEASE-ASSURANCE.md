# Release Assurance and Governance

The release assurance command combines findings, VEX, approved exceptions, provenance status, organizational context, and policy thresholds into a deterministic release decision.

## Decisions and exit codes

| Decision | Exit code | Meaning |
|---|---:|---|
| `PASS` | 0 | No applicable finding meets a warning threshold. |
| `PASS_WITH_WARNINGS` | 2 | Reviewable findings remain below the approval threshold. |
| `APPROVAL_REQUIRED` | 3 | A finding meets the approval threshold. |
| `BLOCK` | 4 | A blocking severity or known-exploited finding is applicable. |
| `INCOMPLETE_EVIDENCE` | 5 | Policy-required evidence is missing. |
| `ERROR` | 10 | Evaluation could not complete. |

Use `--fail-on block|approval|warning|never` to select CI behavior without changing the recorded decision.

## Example

```bash
sst assurance \
  --policy policies/production-release-policy.yml \
  --findings examples/release-assurance/findings.json \
  --vex examples/release-assurance/vex.json \
  --exceptions governance/exceptions.yml \
  --provenance examples/release-assurance/provenance-verification.json \
  --context examples/release-assurance/context.yml \
  --out-dir reports/release-assurance \
  --fail-on never
```

## Exceptions

Exceptions must be approved, scoped, justified, and unexpired before they can exclude a matching finding. Supported scope fields include project, vulnerability, component, package URL, policy rule, and environment.

## Provenance

`sst provenance` correlates artifact and SBOM hashes with provenance subjects, extracts builder identity, and can invoke `cosign verify-blob` when a signature and key are supplied.

## Evidence bundles

`sst evidence-bundle` creates a release evidence directory with file records, sizes, SHA-256 values, a checksum file, and an archive. Optional manifest signing can be requested with a cosign key.
