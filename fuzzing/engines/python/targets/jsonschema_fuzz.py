#!/usr/bin/env python3
"""
Fuzz target: jsonschema (JSON Schema validator)

JSON Schema validation bugs:
- ReDoS in pattern validators
- Complexity exploits in recursive schemas
- Reference resolution bugs
"""

import atheris
import sys
import json

with atheris.instrument_imports():
    import jsonschema
    from jsonschema import Draft7Validator


def TestOneInput(data):
    """Atheris entry point."""
    try:
        # Bound input length
        if len(data) > 20000:
            return

        input_str = data.decode('utf-8', errors='ignore')

        # Try to parse as JSON
        try:
            obj = json.loads(input_str)
        except json.JSONDecodeError:
            return

        # If it's a dict with 'schema' and 'data' keys, validate
        if isinstance(obj, dict):
            if 'schema' in obj and 'data' in obj:
                try:
                    validator = Draft7Validator(obj['schema'])
                    # Validate returns None, but triggers the validation logic
                    validator.validate(obj['data'])
                except jsonschema.SchemaError:
                    # Invalid schema is expected
                    pass
                except jsonschema.ValidationError:
                    # Failed validation is expected
                    pass
            else:
                # Just try to use the object as a schema
                try:
                    validator = Draft7Validator(obj)
                    # Try validating an empty object
                    validator.validate({})
                except jsonschema.SchemaError:
                    pass
                except jsonschema.ValidationError:
                    pass

    except (RecursionError, MemoryError):
        # Real bugs
        raise


if __name__ == '__main__':
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
