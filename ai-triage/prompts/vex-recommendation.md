# VEX Recommendation Prompt

Given a vulnerability, component, scanner evidence, and engineering notes, draft a VEX recommendation.

Rules:

- Never generate `not_affected` without explicit evidence.
- Include the evidence required to support the chosen state.
- Prefer `under_investigation` when evidence is incomplete.
- Mark all output advisory and requiring human approval.
