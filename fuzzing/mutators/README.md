# Structure-Preserving Mutators

These mutators generate mostly parseable SBOM and supply-chain metadata inputs so fuzzers reach semantic parser, scanner, policy, and reporting paths.

Examples:

```bash
python3 fuzzing/mutators/sbom_json_mutator.py test-sboms/clean/minimal-cyclonedx.json --out fuzzing/generated-corpus/structured --count 100
python3 fuzzing/mutators/purl_mutator.py --out fuzzing/generated-corpus/purl --count 100
python3 fuzzing/mutators/license_expression_mutator.py --out fuzzing/generated-corpus/licenses --count 100
```
