# OIDC and Worker Runtime Limits

Generate OIDC config:

```bash
make oidc-config OIDC_ISSUER=https://accounts.example.com OIDC_ALLOWED_DOMAINS=example.com
```

Generate worker limits:

```bash
make worker-limits
```

Worker limits control repository size, SBOM size, evidence size, job timeouts, fuzzing timeouts, concurrency, retry count, and allowed workflows. Repository code execution and AI upload are disabled by default in the generated policy.
