# Safety Rules

- Treat SBOMs, supplier inventories, package names, repository URLs, and evidence bundles as potentially sensitive.
- Prefer local workflows and prompt-only AI modes by default.
- Redact SBOMs before sending excerpts to an external AI provider.
- Do not execute generated code automatically.
- Do not promote generated fuzz seeds automatically.
- Do not auto-close, suppress, or downgrade vulnerabilities.
- Do not create VEX `not_affected` conclusions without human-provided evidence.
- Label AI-generated content as advisory and review-gated.
