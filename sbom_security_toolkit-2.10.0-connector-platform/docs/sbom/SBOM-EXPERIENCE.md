# SBOM Experience Improvements

The toolkit now includes helpers focused on making SBOMs easier to understand, clean up, compare, and share.

## Commands

```bash
make sbom-explain SBOM=your-bom.json
make sbom-normalize SBOM=your-bom.json
make sbom-repair SBOM=your-bom.json
make sbom-inventory SBOM=your-bom.json
make sbom-diff OLD_SBOM=old.json NEW_SBOM=new.json
make sbom-experience SBOM=your-bom.json
```

## Intended use

These commands are not a replacement for a formal SBOM validator. They are designed to reduce friction during supplier intake, security review, scanner troubleshooting, and evidence generation.

## Outputs

- Human-readable SBOM explanation.
- Canonical normalized JSON for diffing and review.
- Best-effort repaired CycloneDX JSON with repair notes.
- CSV/JSON component inventory.
- Component-level diff between two SBOMs.
