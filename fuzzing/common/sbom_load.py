#!/usr/bin/env python3
"""Format-tolerant SBOM loading helpers for fuzzing workflows."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict


def load_json_or_normalized(path: str | Path) -> Dict[str, Any]:
    """Load a JSON SBOM, or normalize XML/SPDX/tag-value into canonical JSON.

    Fuzzing workflows such as metamorphic and round-trip checks operate on JSON
    objects. Users often upload CycloneDX XML from the workbench, so this helper
    falls back to the toolkit canonical normalization instead of crashing with a
    JSONDecodeError.
    """
    p = Path(path)
    raw = p.read_text(errors="replace")
    try:
        doc = json.loads(raw)
        if isinstance(doc, dict):
            return doc
        return {"input": str(p), "format": "json", "value": doc}
    except Exception:
        try:
            from sbomops.normalize import normalized_doc
            doc = normalized_doc(p)
            doc.setdefault("_fuzzing_note", "Input was normalized from a non-JSON SBOM format for this fuzzing workflow.")
            return doc
        except Exception as exc:
            raise ValueError(f"Could not parse {p} as JSON or normalize it as a supported SBOM: {exc}") from exc


def write_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
