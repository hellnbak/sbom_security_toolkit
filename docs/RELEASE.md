# Release Process

1. Update `sbomops/__version__.py` and `pyproject.toml`.
2. Run local validation:

```bash
make test
make validate
make preflight-release
```

3. Build the release package:

```bash
make release VERSION=1.8.0
```

4. Commit, tag, and push:

```bash
git add -A
git commit -m "Prepare v1.8.0 release"
git tag v1.8.0
git push origin main --tags
```

5. Create a GitHub Release and attach the zip/checksum from `dist/`.
