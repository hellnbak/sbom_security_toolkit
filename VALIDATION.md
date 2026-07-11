# Validation — v2.13.0 Actionable Workflows

## Result

All **73 tests passed** when each test module was run in a bounded process. This includes core analysis, packaging, repository intake, dependency health, connectors, release assurance, Workbench, guided experience, actionable UX, cloud mode, AI providers, adaptive fuzzing, and fuzzing operations.

```bash
python3 -m compileall sbomops ai_fuzz fuzzing
for f in tests/test_*.py; do
  PYTHONPATH=. timeout 180 pytest -q "$f"
done
```

The new actionable UX regression suite validates version metadata, the application shell and command palette, all six scan profiles, all seven guided tasks, four persona views, policy simulation, saved local UX state, activity records, and sanitized support-bundle generation.

## External-system limitation

Live third-party writes were not performed because credentials were not supplied. Connector writes remain opt-in and require explicit send/write flags. Offline, configuration, read-only, dry-run, local GUI, and artifact-generation paths were tested.
