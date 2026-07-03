#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def redact_text(text: str, max_chars: int = 12000) -> str:
    """Lightweight prompt redaction to avoid sending obvious secrets or local paths."""
    import re
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "<REDACTED_AWS_ACCESS_KEY>"),
        (r"ASIA[0-9A-Z]{16}", "<REDACTED_AWS_SESSION_KEY>"),
        (r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^\s,'\"]+", r"\1=<REDACTED>"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "<REDACTED_PRIVATE_KEY>"),
        (r"/Users/[^\s\"']+", "/Users/<user>/<path>"),
    ]
    out = text
    for pat, repl in patterns:
        out = re.sub(pat, repl, out, flags=re.DOTALL)
    return out[:max_chars]


def load_json(path: Path) -> Tuple[bool, Any, str]:
    try:
        return True, json.loads(path.read_text(encoding="utf-8")), ""
    except Exception as exc:
        return False, None, str(exc)


def validate_seed(path: Path) -> Dict[str, Any]:
    ok, data, err = load_json(path)
    result: Dict[str, Any] = {"path": str(path), "valid_json": ok, "errors": []}
    if not ok:
        result["errors"].append(err)
        return result
    if not isinstance(data, dict):
        result["errors"].append("top-level value is not an object")
        return result
    if "bomFormat" in data:
        result["format"] = "CycloneDX"
        if "components" not in data:
            result["errors"].append("CycloneDX seed has no components array")
    elif "spdxVersion" in data:
        result["format"] = "SPDX"
        if "packages" not in data:
            result["errors"].append("SPDX seed has no packages array")
    else:
        result["format"] = "unknown"
        result["errors"].append("seed is neither obvious CycloneDX nor SPDX JSON")
    return result


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
