# GLM Local Model Integration

SBOM Security Toolkit can use a GLM-family model as an optional AI provider for AI-assisted fuzzing and SBOM triage workflows.

This integration is intentionally conservative:

- GLM is optional and never required to run the toolkit.
- Prompt-only mode remains the default.
- AI output is advisory.
- Generated seeds, harnesses, tests, and campaigns stay in review queues.
- Generated code is never executed automatically.
- Generated corpus entries are never promoted automatically.
- VEX or exploitability decisions still require human evidence.

## Supported connection patterns

Use the exact model name exposed by your runtime. Depending on how you run the model, it may be named `glm-5.2`, `glm-5`, `zai/glm-5.2`, or something else.

### OpenAI-compatible local endpoint

Point the toolkit at a local OpenAI-compatible server:

```bash
export AI_FUZZ_PROVIDER=glm
export GLM_BASE_URL=http://127.0.0.1:8000/v1
export GLM_MODEL=glm-5.2

make ai-provider-test AI_PROVIDER=glm
make ai-fuzz-seeds AI_PROVIDER=glm FORMAT=cyclonedx SCENARIO=dependency-cycles
make ai-fuzz-campaign AI_PROVIDER=glm GOAL=sbom-parser-hardening
```

You can also use the generic OpenAI-compatible provider directly:

```bash
export AI_FUZZ_PROVIDER=openai-compatible
export OPENAI_COMPATIBLE_BASE_URL=http://127.0.0.1:8000/v1
export AI_FUZZ_MODEL=glm-5.2
```

### Ollama-compatible local endpoint

If your GLM model is exposed through an Ollama-compatible runtime:

```bash
export AI_FUZZ_PROVIDER=ollama
export OLLAMA_HOST=http://127.0.0.1:11434
export AI_FUZZ_MODEL=glm-5

make ai-provider-test AI_PROVIDER=ollama AI_MODEL=glm-5
```

## Provider configs

Example configs live under:

```text
ai_fuzz/config/glm-5.2-local.yml
ai_fuzz/config/glm-ollama.yml
```

These are reference profiles, not secrets. They intentionally use local loopback defaults.

## Recommended GLM use cases

Good uses:

- fuzz seed ideas;
- mutation-plan drafts;
- crash triage summaries;
- regression-test draft generation;
- fuzz campaign planning;
- scanner-disagreement explanations;
- supplier follow-up question drafting.

Avoid using any model, local or hosted, for:

- automatic vulnerability suppression;
- final VEX `not_affected` decisions;
- automatic exploitability conclusions;
- executing generated fuzz harnesses without review;
- committing generated tests without review.

## Review flow

AI output lands under:

```text
ai_fuzz/review/incoming/
```

Then use:

```bash
make ai-review-list
make ai-review-accept ITEM=<folder-name>
make ai-review-reject ITEM=<folder-name>
```

Acceptance only moves the artifact to the accepted review queue. It does not automatically execute code, modify the regression corpus, or change vulnerability decisions.
