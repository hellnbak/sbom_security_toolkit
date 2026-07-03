#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .providers import complete, provider_defaults

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ai-provider-test",
        description="Test an optional AI provider configuration without running a fuzzing workflow.",
    )
    parser.add_argument("--provider", default=os.environ.get("AI_FUZZ_PROVIDER", "none"), help="none, ollama, openai-compatible, or glm")
    parser.add_argument("--model", default=None, help="Override provider model name")
    parser.add_argument("--prompt", default="Return the single word OK.", help="Small prompt used for provider validation")
    parser.add_argument("--out", default="reports/ai-provider-test.json", help="Where to write provider test result JSON")
    args = parser.parse_args()

    provider_name, model_name = provider_defaults(args.provider, args.model)
    result = complete(args.prompt, provider=provider_name, model=model_name, timeout=30)

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "requested_provider": args.provider,
        "resolved_provider": result.provider,
        "model": result.model,
        "used_network": result.used_network,
        "ok": result.error is None,
        "error": result.error,
        "text_preview": (result.text or "")[:200],
        "safety": {
            "advisory_only": True,
            "review_required": True,
            "auto_execute_generated_code": False,
            "auto_promote_corpus": False,
        },
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")
    try:
        display_out = str(out.relative_to(ROOT))
    except ValueError:
        display_out = str(out)
    print(f"provider={payload['resolved_provider']} model={payload['model']} ok={payload['ok']} out={display_out}")
    if result.error:
        print(f"warning: provider returned an error: {result.error}")
    return 0 if payload["ok"] or result.provider == "none" else 1


if __name__ == "__main__":
    raise SystemExit(main())
