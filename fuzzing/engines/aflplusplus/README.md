# AFL++ SBOM Fuzzing Scaffold

This directory contains a local-first AFL++ integration scaffold. It is intentionally conservative: it does not download or execute AFL++ automatically. Use it when you want to connect the toolkit's structure-aware mutators and dictionaries to AFL++ campaigns.

Recommended workflow:

```bash
make fuzz-generate-cyclonedx COUNT=100
make fuzz-afl-cyclonedx
```

The custom mutator bridge is a Python-compatible interface that can reuse `fuzzing/mutators/*` logic. Wire it into your AFL++ container or local AFL++ installation.
