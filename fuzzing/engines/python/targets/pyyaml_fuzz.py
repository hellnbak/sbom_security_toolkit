#!/usr/bin/env python3
"""
Fuzz target: PyYAML (YAML parser)

YAML parsers have consistent security issues:
- Alias expansion (billion laughs)
- Deep nesting (stack exhaustion)
- Type confusion
- ReDoS in various patterns

This follows the Atheris pattern: define a TestOneInput function.
"""

import atheris
import sys

with atheris.instrument_imports():
    import yaml


def TestOneInput(data):
    """Atheris entry point - called with each fuzzed input."""
    try:
        # Bound input length to avoid trivial OOM
        if len(data) > 50000:
            return

        # Decode to string
        input_str = data.decode('utf-8', errors='ignore')

        # Parse YAML with safe loader (no arbitrary code execution)
        parsed = yaml.safe_load(input_str)

        # Force evaluation of the result
        if parsed is not None:
            # This will raise on circular references
            str(parsed)

    except yaml.YAMLError:
        # Expected parse errors are fine
        pass
    except (RecursionError, MemoryError):
        # These are real bugs - let them propagate
        raise


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
