#!/usr/bin/env python3
"""
call_claude.py — single entry point for calling Claude, used by ai-triage.sh
and any other script here that needs a text completion. Supports two
backends so the same toolkit works unmodified on a laptop and on the EC2/
Bedrock deployment:

  --backend direct   (default) Anthropic's own API, needs ANTHROPIC_API_KEY.
  --backend bedrock  Amazon Bedrock, auth via the normal AWS credential chain
                      (on EC2: an attached instance role — no static keys).

BEDROCK IMPLEMENTATION — this delegates to Claude Code, not the SDK directly:
The first version of this called anthropic's Bedrock SDK clients
(AnthropicBedrockMantle / AnthropicBedrock) directly. In real deployment that
hit confirmed, repeated permission and model-ID complexity — Mantle denying
bedrock-mantle:CreateInference even after granting it in IAM, then the
legacy client rejecting the bare model ID because it wants an inference-
profile ARN it isn't given. Meanwhile Claude Code's OWN Bedrock integration
(CLAUDE_CODE_USE_BEDROCK=1) worked cleanly on the same account, same role,
same run — it's evidently resolving the inference-profile question
correctly, internally. So this now shells out to `claude -p` when Claude
Code is on PATH, and only falls back to the direct SDK dance if it isn't
(e.g. a minimal container with just the anthropic package). If you hit
Bedrock trouble here, installing Claude Code is the more reliable fix than
debugging the SDK fallback further.

Install:
    pip install "anthropic[bedrock]"                          # newer pip
    pip install "anthropic[bedrock]" --break-system-packages   # if that's refused
    (--break-system-packages was pip 23+; older pip like AL2023's default
    3.9 install (21.3.1) doesn't recognize it at all and errors on the flag
    itself, so try without it first — see call_direct/call_bedrock below,
    which suggest the same order.)

Usage:
    python3 call_claude.py --backend direct  --system "..." --prompt "..." [--model claude-sonnet-5] [--max-tokens 4096]
    python3 call_claude.py --backend bedrock --system "..." --prompt "..." [--region us-east-1]

Prompt/system can also be piped via --prompt-file/--system-file to avoid
fighting shell quoting on large inputs (this is what ai-triage.sh uses).
Prints the response text to stdout; nothing else, so it's pipeline-friendly.
"""
from __future__ import annotations  # lets `str | None` work on Python < 3.10 —
                                     # AL2023's default python3 is older than that,
                                     # and this failed there without this line.
import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def read_arg_or_file(value: str | None, file_path: str | None, name: str) -> str | None:
    if file_path:
        with open(file_path, encoding="utf-8") as f:
            return f.read()
    return value


def call_direct(system: str | None, prompt: str, model: str, max_tokens: int) -> str:
    try:
        import anthropic
    except ImportError:
        sys.exit("python3 -m pip install anthropic || "
                 "python3 -m pip install anthropic --break-system-packages")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        sys.exit("--backend direct needs ANTHROPIC_API_KEY set.")

    client = anthropic.Anthropic(api_key=api_key)
    kwargs = {"model": model, "max_tokens": max_tokens,
              "messages": [{"role": "user", "content": prompt}]}
    if system:
        kwargs["system"] = system
    resp = client.messages.create(**kwargs)
    return "".join(b.text for b in resp.content if b.type == "text")


def call_bedrock(system: str | None, prompt: str, model: str, max_tokens: int, region: str) -> str:
    # Prefer delegating to Claude Code itself, if it's installed. Its own
    # Bedrock integration (CLAUDE_CODE_USE_BEDROCK=1) is proven working on
    # real deployments of this toolkit — orchestrate.sh's Stage 3 uses it
    # successfully — while this function's own direct-SDK attempts below
    # hit real, confirmed permission/model-ID complexity on the same
    # account (bedrock-mantle:CreateInference denials, then legacy
    # AnthropicBedrock rejecting the bare model ID because it wants an
    # inference-profile ARN it isn't given). Claude Code evidently resolves
    # that correctly internally; reuse it rather than keep re-deriving
    # Bedrock's newest, least-documented invocation details from outside.
    claude_cli = shutil.which("claude")
    if claude_cli:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        # NOT passed as a CLI argument or via stdin — confirmed the hard way
        # (OSError: Argument list too long) that ai-triage.sh's prompts (up
        # to ~300KB of scanner JSON) blow past the OS argument-length limit,
        # and Claude Code's own docs flag large stdin as having had issues
        # historically (a documented bug returns empty output on large
        # piped input) and explicitly recommend a file reference instead for
        # large inputs. Write it to a temp file and have Claude Code read it
        # via its own Read tool — the same mechanism orchestrate.sh's Stage
        # 3 already uses successfully, just applied here too.
        #
        # Argument ORDER matters: --allowedTools evidently consumes tokens
        # greedily until the next --flag, not just one value — confirmed the
        # hard way again ("Input must be provided..." error) when the prompt
        # immediately followed --allowedTools Read with nothing in between,
        # which swallowed the prompt text as if it were more tool names. The
        # working Stage 3 invocation always has another --flag between
        # --allowedTools's value and the final prompt; this now matches that
        # structure exactly rather than trusting an unverified ordering.
        prompt_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False,
                                              prefix="call_claude_prompt_") as f:
                f.write(full_prompt)
                prompt_file = f.name

            result = subprocess.run(
                [claude_cli, "-p",
                 "--allowedTools", "Read",
                 "--max-turns", "30",
                 "--output-format", "text",
                 f"Read the file at {prompt_file} in full and follow its "
                 f"instructions exactly. Output only what those instructions "
                 f"ask for — no preamble, no mention of having read a file."],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            print(f"[call_claude.py] claude -p failed (exit {result.returncode}). "
                  f"stdout: {result.stdout.strip()!r} stderr: {result.stderr.strip()!r} "
                  f"— falling back to direct SDK calls.", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print("[call_claude.py] claude -p timed out after 300s; "
                  "falling back to direct SDK calls.", file=sys.stderr)
        finally:
            if prompt_file and os.path.exists(prompt_file):
                os.unlink(prompt_file)

    return _call_bedrock_sdk(system, prompt, model, max_tokens, region)


def _call_bedrock_sdk(system: str | None, prompt: str, model: str, max_tokens: int, region: str) -> str:
    # Fallback for environments without Claude Code installed (e.g. a
    # minimal container running only ai-triage.sh). Tries the newer Mantle
    # endpoint (needed for Sonnet 5+) first, then the legacy AnthropicBedrock
    # client. Both have had real permission/model-ID issues in testing —
    # this exists as a documented last resort, not a guaranteed-working path.
    # If it fails, installing Claude Code and letting the branch above
    # handle it is the more reliable option.
    try:
        import anthropic
    except ImportError:
        sys.exit('python3 -m pip install "anthropic[bedrock]" || '
                 'python3 -m pip install "anthropic[bedrock]" --break-system-packages')

    kwargs = {"model": model, "max_tokens": max_tokens,
              "messages": [{"role": "user", "content": prompt}]}
    if system:
        kwargs["system"] = system

    if hasattr(anthropic, "AnthropicBedrockMantle"):
        try:
            client = anthropic.AnthropicBedrockMantle(aws_region=region)
            resp = client.messages.create(**kwargs)
            return "".join(b.text for b in resp.content if b.type == "text")
        except Exception as e:
            print(f"[call_claude.py] Mantle endpoint failed ({e}); "
                  f"falling back to legacy AnthropicBedrock client.", file=sys.stderr)

    if not hasattr(anthropic, "AnthropicBedrock"):
        sys.exit(
            "Neither AnthropicBedrockMantle nor AnthropicBedrock is available in "
            "the installed 'anthropic' package, and Claude Code isn't on PATH "
            "either. Easiest fix: npm install -g @anthropic-ai/claude-code. "
            "Otherwise: python3 -m pip install -U \"anthropic[bedrock]\" and "
            "check https://docs.claude.com/en/build-with-claude/claude-on-amazon-bedrock "
            "for what's current — this endpoint has moved fast."
        )
    client = anthropic.AnthropicBedrock(aws_region=region)
    # Legacy client generally wants a region- or global-prefixed, ARN-style
    # model id (e.g. "global.anthropic.claude-opus-4-6-v1") or a full
    # inference-profile ARN, not the bare "anthropic.claude-sonnet-5" the
    # Mantle path uses — confirmed failing with exactly that complaint in
    # testing. Installing Claude Code so the branch above handles this
    # instead is more reliable than hand-deriving the right ARN here.
    resp = client.messages.create(**kwargs)
    return "".join(b.text for b in resp.content if b.type == "text")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--backend", choices=["direct", "bedrock"], default=os.environ.get("CLAUDE_BACKEND", "direct"))
    ap.add_argument("--system")
    ap.add_argument("--system-file")
    ap.add_argument("--prompt")
    ap.add_argument("--prompt-file")

    # Backend-aware default model: Bedrock uses versioned model IDs with dates;
    # Direct API uses simple names. Check CLAUDE_BACKEND early so the default
    # matches what will actually be used.
    backend_default = os.environ.get("CLAUDE_BACKEND", "direct")
    if backend_default == "bedrock":
        default_model = "claude-3-5-sonnet-20241022-v2:0"  # Latest Claude 3.5 Sonnet for Bedrock
    else:
        default_model = "claude-sonnet-4-5"  # Direct API (requires ANTHROPIC_API_KEY)

    ap.add_argument("--model",
                    default=os.environ.get("CLAUDE_MODEL", default_model),
                    help=f"Model to use. Defaults to {default_model} for {backend_default} backend. "
                         "Override via CLAUDE_MODEL env var or this argument.")
    ap.add_argument("--max-tokens", type=int, default=4096)
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"),
                     help="Bedrock only. Model availability varies by region — verify in the console.")
    args = ap.parse_args()

    system = read_arg_or_file(args.system, args.system_file, "system")
    prompt = read_arg_or_file(args.prompt, args.prompt_file, "prompt")
    if not prompt:
        sys.exit("Provide --prompt or --prompt-file")

    if args.backend == "bedrock":
        # Bedrock's Mantle model naming mirrors the direct API's bare model
        # string (e.g. "claude-sonnet-5"); the AWS blog announcing it on
        # Bedrock shows "anthropic.claude-sonnet-5" specifically for that
        # endpoint. Adjust the prefix here if your account needs a different
        # one — see the big warning in this file's docstring.
        model = args.model if args.model.startswith("anthropic.") else f"anthropic.{args.model}"
        text = call_bedrock(system, prompt, model, args.max_tokens, args.region)
    else:
        text = call_direct(system, prompt, args.model, args.max_tokens)

    print(text)


if __name__ == "__main__":
    main()
