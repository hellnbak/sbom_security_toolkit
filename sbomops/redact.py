#!/usr/bin/env python3
from __future__ import annotations
import argparse, copy, hashlib, json, re
from pathlib import Path
from .common import detect_format

INTERNAL_PATTERNS = [re.compile(p, re.I) for p in [r"internal", r"private", r"corp", r"company", r"localhost", r"\.local", r"/Users/[^/]+", r"C:\\\\Users\\\\[^\\\\]+"]]


def h(value, salt="sbom-security-toolkit"):
    return "redacted-" + hashlib.sha256((salt + str(value)).encode()).hexdigest()[:12]


def redact_string(s, hash_names=False):
    if not isinstance(s, str): return s
    red = re.sub(r"https?://[^\s\"']+", "REDACTED_URL", s)
    red = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "REDACTED_EMAIL", red)
    red = re.sub(r"/Users/[^/\s]+", "/Users/REDACTED", red)
    red = re.sub(r"C:\\\\Users\\\\[^\\\s]+", r"C:\\Users\\REDACTED", red)
    if hash_names and any(p.search(red) for p in INTERNAL_PATTERNS):
        return h(red)
    return red


def redact_obj(obj, hash_names=False):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = k.lower()
            if kl in {"supplier", "author", "authors", "publisher", "externalreferences", "externalRefs".lower()}:
                out[k] = "REDACTED" if isinstance(v, str) else redact_obj(v, hash_names)
            elif kl in {"url", "repository", "downloadlocation", "homepage"}:
                out[k] = "REDACTED_URL"
            elif hash_names and kl in {"name", "group", "bom-ref", "spdxid"} and isinstance(v, str) and any(p.search(v) for p in INTERNAL_PATTERNS):
                out[k] = h(v)
            else:
                out[k] = redact_obj(v, hash_names)
        return out
    if isinstance(obj, list):
        return [redact_obj(x, hash_names) for x in obj]
    if isinstance(obj, str):
        return redact_string(obj, hash_names)
    return obj


def main():
    ap = argparse.ArgumentParser(description="Redact sensitive/internal SBOM metadata for safe sharing.")
    ap.add_argument("sbom"); ap.add_argument("--out", default="reports/redacted-sbom.json"); ap.add_argument("--hash-internal-names", action="store_true")
    args = ap.parse_args()
    fmt = detect_format(args.sbom)
    raw = Path(args.sbom).read_text(encoding="utf-8", errors="replace")
    if fmt.endswith("json") or raw.lstrip().startswith("{"):
        data = json.loads(raw)
        redacted = redact_obj(data, args.hash_internal_names)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(redacted, indent=2) + "\n", encoding="utf-8")
    else:
        red = redact_string(raw, args.hash_internal_names)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(red, encoding="utf-8")
    print(args.out)

if __name__ == "__main__":
    main()
