#!/usr/bin/env python3
"""Atheris target for package-url / purl parsing edge cases."""
import atheris
import sys
from urllib.parse import parse_qsl, unquote, urlsplit
MAX_BYTES = 8_192

def parse_purl_like(value: str):
    if not value.startswith("pkg:"):
        return None
    split = urlsplit(value)
    body = value[4:]
    qualifiers = {}
    if "?" in body:
        body, query = body.split("?", 1)
        qualifiers = dict(parse_qsl(query, keep_blank_values=True, strict_parsing=False))
    subpath = None
    if "#" in body:
        body, subpath = body.split("#", 1)
    parts = [unquote(p) for p in body.split("/")]
    return {"scheme": split.scheme, "type": parts[0] if parts else "", "namespace": parts[1:-1], "name_version": parts[-1] if parts else "", "qualifiers": qualifiers, "subpath": subpath}

def TestOneInput(data: bytes) -> None:
    if len(data) > MAX_BYTES:
        return
    try:
        text = data.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return
    parsed = parse_purl_like(text)
    if parsed is None:
        return
    repr(parsed).encode("utf-8", errors="strict")

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
