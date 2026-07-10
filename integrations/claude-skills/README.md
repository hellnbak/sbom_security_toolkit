# Claude Skills Integration

This directory contains an optional Claude Skill for SBOM Security Toolkit.

The skill does not replace the toolkit, run scanners by itself, or make vulnerability decisions. It gives Claude/Claude Code reusable instructions, command references, safety rules, and workflow guidance for using the toolkit correctly.

## Installation

Copy the `sbom-security-toolkit` directory into your Claude Skills location, or import it through the Claude UI where custom Skills are supported.

```bash
cp -R integrations/claude-skills/sbom-security-toolkit <your-claude-skills-directory>/
```

Then ask Claude to help with workflows such as:

- analyze a supplier SBOM with SBOM Security Toolkit
- explain a policy failure
- triage a fuzzing crash
- draft a supplier follow-up from an evidence bundle
- create a safe AI-assisted fuzzing campaign plan

## Safety model

The skill follows the same safety model as the toolkit:

- AI suggests; deterministic tooling validates; humans approve.
- Do not submit sensitive SBOMs to external providers unless the user explicitly approves.
- Redact SBOMs before sharing excerpts outside the local environment.
- Do not mark VEX or exploitability states as `not_affected` without human evidence.
- Do not execute AI-generated fuzz harnesses or code automatically.
