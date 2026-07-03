# crash-triage

Use this prompt template with the AI fuzzing CLI. The model should produce defensive, reviewable fuzzing artifacts only.

Rules:
- Do not include exploit code or live targets.
- Do not include secrets or credentials.
- Keep outputs bounded and human-reviewable.
- Prefer SBOM structure, parser edge cases, semantic oracles, and regression ideas.
- Generated artifacts must not be executed automatically.
