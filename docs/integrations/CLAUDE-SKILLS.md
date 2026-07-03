# Claude Skills Integration

SBOM Security Toolkit includes an optional Claude Skill under `integrations/claude-skills/sbom-security-toolkit`.

The skill helps Claude or Claude Code guide users through toolkit workflows, including SBOM intake, policy evaluation, supplier questions, fuzzing triage, release evidence review, and AI-assisted fuzzing campaign planning.

## Why this is optional

The toolkit remains provider-neutral and local-first. Claude Skills are an integration layer, not a runtime dependency. All core workflows continue to work through `make`, `sst`, and the local workbench UI.

## Install

Copy the skill directory into your Claude Skills location or import it through the Claude UI where custom Skills are supported.

```bash
cp -R integrations/claude-skills/sbom-security-toolkit <your-claude-skills-directory>/
```

## What the skill does

The skill provides:

- command references;
- safety rules;
- workflow maps;
- report interpretation guidance;
- small helper scripts for analysis, report listing, and fuzzing crash triage.

## What the skill does not do

The skill does not:

- replace scanners;
- replace deterministic policy gates;
- automatically declare vulnerabilities exploitable or not exploitable;
- automatically promote AI-generated fuzzing seeds;
- automatically execute AI-generated fuzz harnesses;
- require users to send SBOM data to external AI providers.

## Recommended use

Use the skill to ask questions such as:

- “Which command should I run for this supplier SBOM?”
- “Explain this policy failure without overstating risk.”
- “Turn this scanner disagreement into likely causes and next actions.”
- “Triage this fuzzing crash and suggest a regression test plan.”
- “Create a safe AI-assisted fuzzing campaign for CycloneDX parser hardening.”
