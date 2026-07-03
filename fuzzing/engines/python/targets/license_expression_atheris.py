#!/usr/bin/env python3
"""Atheris target for SPDX-style license expression tokenization."""
import atheris
import re
import sys
MAX_BYTES = 16_384
TOKEN_RE = re.compile(r"\(|\)|WITH|AND|OR|[A-Za-z0-9-.+]+")

def validate_balance(tokens):
    depth = 0; max_depth = 0
    for token in tokens[:10_000]:
        if token == "(":
            depth += 1; max_depth = max(max_depth, depth)
        elif token == ")":
            depth -= 1
        if depth < -1000:
            break
    return depth, max_depth

def TestOneInput(data: bytes) -> None:
    if len(data) > MAX_BYTES:
        return
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return
    tokens = TOKEN_RE.findall(text)
    if not tokens:
        return
    validate_balance(tokens)
    normalized = " ".join(tokens[:5000]).replace(" and ", " AND ").replace(" or ", " OR ")
    normalized.encode("ascii", errors="ignore")

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
