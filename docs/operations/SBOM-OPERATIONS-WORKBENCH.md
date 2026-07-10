# SBOM Operations Workbench

This toolkit is intended to be a practical SBOM security operations workbench, not a replacement for mature scanners or enterprise SCA platforms.

Core workflows:

1. Validate and score SBOM quality.
2. Apply policy-as-code gates.
3. Enrich and prioritize vulnerability findings.
4. Compare scanner output and investigate disagreement.
5. Review supplier-provided SBOMs.
6. Create and validate VEX statements with human review.
7. Generate release evidence bundles.
8. Use fuzzing to test SBOM parser and scanner robustness.

## Recommended operating model

- Treat scanner output as evidence, not truth.
- Use VEX only when engineering has supporting evidence.
- Keep SBOMs, VEX, scanner reports, and policy results as release artifacts.
- Run short checks in pull requests and deeper checks on schedules or releases.
- Preserve crash reproducers from fuzzing campaigns.
