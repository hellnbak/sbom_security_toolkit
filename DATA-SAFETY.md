# Data Safety

This repository is intended to contain synthetic SBOMs, fuzzing corpora, demonstration data, and local-only workflow scaffolding.

Do **not** commit:

- production SBOMs
- vendor/customer SBOMs
- customer names or domains
- internal package names that disclose private systems
- secrets, API keys, tokens, or credentials
- proprietary component inventories
- generated reports that include sensitive findings
- workbench uploads or job output

Before publishing a release, run:

```bash
make preflight-release
```

The preflight script checks for generated artifacts, Python cache files, common secret patterns, and known company/customer-specific terms that should not appear in the public release package.
