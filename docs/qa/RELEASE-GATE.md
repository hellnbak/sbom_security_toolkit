# QA and Release Gate

Use these targets before tagging releases:

```bash
make test-fast
make test-integration-offline
make test-fuzz-smoke
make test-release
```

`make test-all` runs the broader local suite and can take longer because fuzzing workflows intentionally spawn subprocesses.
