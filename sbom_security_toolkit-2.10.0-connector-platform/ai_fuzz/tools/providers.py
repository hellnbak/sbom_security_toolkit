#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProviderResult:
    provider: str
    model: str
    text: str
    used_network: bool
    error: Optional[str] = None


class ProviderError(RuntimeError):
    pass


def configured_provider(explicit: Optional[str] = None) -> str:
    return (explicit or os.environ.get("AI_FUZZ_PROVIDER") or "none").strip().lower()


def provider_defaults(provider: Optional[str], model: Optional[str] = None) -> tuple[str, str]:
    """Resolve provider aliases and safe default model names.

    Providers are optional. If a provider is unavailable or misconfigured, callers
    should fall back to prompt/review artifacts instead of failing closed in a
    way that hides useful fuzzing context.
    """
    provider_name = configured_provider(provider)
    if provider_name in {"glm", "glm-5", "glm-5.2", "zai", "zhipu"}:
        return "glm", model or os.environ.get("GLM_MODEL") or os.environ.get("AI_FUZZ_MODEL") or "glm-5.2"
    if provider_name == "ollama":
        return "ollama", model or os.environ.get("AI_FUZZ_MODEL") or os.environ.get("GLM_MODEL") or "llama3.1"
    if provider_name in {"openai", "openai-compatible", "compatible"}:
        return "openai-compatible", model or os.environ.get("AI_FUZZ_MODEL") or "local-model"
    if provider_name in {"bedrock", "amazon-bedrock", "aws-bedrock", "aws"}:
        return "bedrock", model or os.environ.get("BEDROCK_MODEL_ID") or os.environ.get("AWS_BEDROCK_MODEL_ID") or os.environ.get("AI_FUZZ_MODEL") or "bedrock-model-id"
    if provider_name in {"", "none", "prompt", "prompt-only"}:
        return "none", model or "none"
    return provider_name, model or os.environ.get("AI_FUZZ_MODEL") or "local-model"


def complete(prompt: str, *, provider: Optional[str] = None, model: Optional[str] = None, timeout: int = 60) -> ProviderResult:
    """Return model text or a prompt-only placeholder.

    Supported providers:
      - none: no network call, returns empty advisory text
      - ollama: POST to OLLAMA_HOST/api/generate, default http://127.0.0.1:11434
      - openai-compatible: POST to OPENAI_COMPATIBLE_BASE_URL/chat/completions
      - glm: OpenAI-compatible local GLM profile; default model glm-5.2
      - bedrock: optional AWS Bedrock provider using boto3 Converse API
    """
    provider_name, model_name = provider_defaults(provider, model)
    if provider_name == "none":
        return ProviderResult(provider="none", model=model_name, text="", used_network=False)
    if provider_name == "ollama":
        return _ollama(prompt, model=model_name, timeout=timeout)
    if provider_name == "openai-compatible":
        return _openai_compatible(prompt, model=model_name, timeout=timeout)
    if provider_name == "glm":
        return _openai_compatible(prompt, model=model_name, timeout=timeout, provider_label="glm")
    if provider_name == "bedrock":
        return _bedrock(prompt, model=model_name, timeout=timeout)
    raise ProviderError(f"Unsupported AI_FUZZ_PROVIDER: {provider_name}")


def _ollama(prompt: str, *, model: str, timeout: int) -> ProviderResult:
    base = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(f"{base}/api/generate", data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return ProviderResult(provider="ollama", model=model, text=data.get("response", ""), used_network=True)
    except Exception as exc:
        return ProviderResult(provider="ollama", model=model, text="", used_network=True, error=str(exc))


def _openai_compatible(prompt: str, *, model: str, timeout: int, provider_label: str = "openai-compatible") -> ProviderResult:
    base = (os.environ.get("GLM_BASE_URL") if provider_label == "glm" else None) or os.environ.get("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1")
    base = base.rstrip("/")
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("AI_FUZZ_API_KEY") or "local"
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are assisting defensive fuzzing of SBOM parsers. Return concise, reviewable artifacts only."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return ProviderResult(provider=provider_label, model=model, text=text, used_network=True)
    except Exception as exc:
        return ProviderResult(provider=provider_label, model=model, text="", used_network=True, error=str(exc))


def _bedrock(prompt: str, *, model: str, timeout: int) -> ProviderResult:
    """Call AWS Bedrock in an optional/dependency-light way.

    boto3 is intentionally optional so the toolkit still installs and tests
    without AWS dependencies. Bedrock credentials/region are resolved by the
    normal AWS SDK provider chain; no keys or tokens are stored by the toolkit.
    """
    if model == "bedrock-model-id":
        return ProviderResult(provider="bedrock", model=model, text="", used_network=True, error="Set BEDROCK_MODEL_ID, AWS_BEDROCK_MODEL_ID, AI_FUZZ_MODEL, or pass --model.")
    try:
        import boto3  # type: ignore
        from botocore.config import Config  # type: ignore
    except Exception as exc:
        return ProviderResult(provider="bedrock", model=model, text="", used_network=True, error=f"boto3/botocore not installed: {exc}")
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("BEDROCK_REGION") or "us-east-1"
    try:
        client = boto3.client("bedrock-runtime", region_name=region, config=Config(read_timeout=timeout, connect_timeout=min(timeout, 10)))
        response = client.converse(
            modelId=model,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            system=[{"text": "You are assisting defensive fuzzing of SBOM parsers. Return concise, reviewable artifacts only."}],
            inferenceConfig={"temperature": 0.2, "maxTokens": 1600},
        )
        chunks = []
        for item in response.get("output", {}).get("message", {}).get("content", []):
            if "text" in item:
                chunks.append(item["text"])
        return ProviderResult(provider="bedrock", model=model, text="\n".join(chunks), used_network=True)
    except Exception as exc:
        return ProviderResult(provider="bedrock", model=model, text="", used_network=True, error=str(exc))


def render_or_call(provider: str, prompt: str, *, model: str = "") -> str:
    """Return provider output, or a prompt-only review artifact when provider is disabled/unavailable."""
    result = complete(prompt, provider=provider, model=model or None)
    if result.text:
        return result.text
    header = f"# Prompt-only AI artifact\n\nProvider: {result.provider}\nModel: {result.model}\n"
    if result.error:
        header += f"Provider error: {result.error}\n"
    return header + "\nReview this prompt manually or configure a local provider.\n\n```text\n" + prompt + "\n```\n"
