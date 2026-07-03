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


def complete(prompt: str, *, provider: Optional[str] = None, model: Optional[str] = None, timeout: int = 60) -> ProviderResult:
    """Return model text or a prompt-only placeholder.

    Supported providers:
      - none: no network call, returns empty advisory text
      - ollama: POST to OLLAMA_HOST/api/generate, default http://127.0.0.1:11434
      - openai-compatible: POST to OPENAI_COMPATIBLE_BASE_URL/chat/completions
    """
    provider_name = configured_provider(provider)
    if provider_name in {"", "none", "prompt", "prompt-only"}:
        return ProviderResult(provider="none", model=model or "none", text="", used_network=False)
    if provider_name == "ollama":
        return _ollama(prompt, model=model or os.environ.get("AI_FUZZ_MODEL") or "llama3.1", timeout=timeout)
    if provider_name in {"openai", "openai-compatible", "compatible"}:
        return _openai_compatible(prompt, model=model or os.environ.get("AI_FUZZ_MODEL") or "local-model", timeout=timeout)
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


def _openai_compatible(prompt: str, *, model: str, timeout: int) -> ProviderResult:
    base = os.environ.get("OPENAI_COMPATIBLE_BASE_URL", "http://127.0.0.1:8000/v1").rstrip("/")
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
        return ProviderResult(provider="openai-compatible", model=model, text=text, used_network=True)
    except Exception as exc:
        return ProviderResult(provider="openai-compatible", model=model, text="", used_network=True, error=str(exc))
