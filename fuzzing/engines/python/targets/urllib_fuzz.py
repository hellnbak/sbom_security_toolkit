#!/usr/bin/env python3
"""
Fuzz target: urllib3 (HTTP client library)

URL parsing and HTTP handling bugs:
- URL parsing inconsistencies (SSRF)
- Header injection
- Request smuggling patterns
"""

import atheris
import sys

with atheris.instrument_imports():
    from urllib3.util import parse_url
    from urllib3.exceptions import LocationParseError


def TestOneInput(data):
    """Atheris entry point."""
    try:
        # Bound input length
        if len(data) > 2000:
            return

        input_str = data.decode('utf-8', errors='ignore')

        # Try to parse as URL
        try:
            parsed = parse_url(input_str)
            # Force evaluation of all properties
            if parsed:
                _ = parsed.scheme
                _ = parsed.host
                _ = parsed.port
                _ = parsed.path
                _ = parsed.query
        except LocationParseError:
            # Expected parse errors
            pass

    except (RecursionError, MemoryError, ValueError):
        # Real bugs or unexpected errors
        raise


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
