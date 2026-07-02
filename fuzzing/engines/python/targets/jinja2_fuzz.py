#!/usr/bin/env python3
"""
Fuzz target: Jinja2 (template engine)

Template engines are high-value targets:
- Template injection vulnerabilities
- Parser bugs in variable expressions
- ReDoS in template syntax
- Filter/function vulnerabilities
"""

import atheris
import sys

with atheris.instrument_imports():
    from jinja2 import Environment, TemplateSyntaxError, UndefinedError
    from jinja2.sandbox import SandboxedEnvironment


def TestOneInput(data):
    """Atheris entry point."""
    try:
        # Bound input length
        if len(data) > 10000:
            return

        input_str = data.decode('utf-8', errors='ignore')

        # Use sandboxed environment to prevent code execution
        env = SandboxedEnvironment()

        # Try to compile the template
        template = env.from_string(input_str)

        # Try to render with empty context
        # (Most templates will fail here, that's expected)
        try:
            result = template.render({})
            # Force evaluation
            len(result)
        except (UndefinedError, TypeError, ValueError):
            # Expected template errors
            pass

    except TemplateSyntaxError:
        # Expected parse errors
        pass
    except (RecursionError, MemoryError):
        # Real bugs
        raise


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
