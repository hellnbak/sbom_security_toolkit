# Semantic Oracles

Semantic oracles catch fuzzing failures that do not crash a process, such as silent component drops, dependency graph loss, duplicate identifiers, and unexpected parse/normalize behavior.

```bash
python3 fuzzing/oracles/semantic_oracles.py test-sboms/clean/minimal-cyclonedx.json
python3 fuzzing/oracles/semantic_oracles.py before.json --after after.json
```
