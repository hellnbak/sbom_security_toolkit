# Command Reference

## Quality

```bash
make sbom-score SBOM=vuln-scan/cyclonedx-sbom.xml
```

## Policy

```bash
make policy-check SBOM=vuln-scan/cyclonedx-sbom.xml POLICY=policies/default-release-policy.yml
```

## Supplier intake

```bash
make supplier-intake SBOM=test-sboms/supplier-intake/incomplete-supplier-sbom.json
```

## VEX

```bash
make vex-template CVE=CVE-2099-0001 COMPONENT=pkg:pypi/example-lib@1.0.0 STATE=under_investigation
make vex-validate VEX=vex/examples/not_affected.cdx.json
make vex-explain VEX=vex/examples/not_affected.cdx.json
```

## Reports and UI

```bash
make report SBOM=vuln-scan/cyclonedx-sbom.xml
make ui
open reports/ui/index.html
```

## Demo

```bash
make demo
```
