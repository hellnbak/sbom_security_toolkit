#!/usr/bin/env python3
"""
Extract ecosystems from components.json and map to fuzzing engines.

Usage:
    python3 detect-ecosystems.py components.json

Output: One line per ecosystem with engine support
    composer:91:php
    npm:42:javascript
    pypi:15:python
    maven:8:java
    golang:5:go
    cargo:3:rust
    gem:2:none
"""

import json
import re
import sys
from collections import Counter


ECOSYSTEM_TO_ENGINE = {
    'composer': 'php',
    'npm': 'javascript',
    'pypi': 'python',
    'maven': 'java',
    'golang': 'go',
    'cargo': 'rust',
    # Future engines:
    'gem': 'none',      # Ruby - no mature fuzzer yet
    'nuget': 'none',    # .NET - SharpFuzz exists but needs evaluation
}


def main():
    if len(sys.argv) < 2:
        print("Usage: detect-ecosystems.py components.json", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        components = json.load(f)

    ecosystems = Counter()
    for component in components:
        purl = component.get('purl') or ''
        if purl:
            m = re.match(r'pkg:([^/]+)/', purl)
            if m:
                ecosystems[m.group(1)] += 1

    # Output: ecosystem:count:engine
    for eco, count in sorted(ecosystems.items(), key=lambda x: -x[1]):
        engine = ECOSYSTEM_TO_ENGINE.get(eco, 'none')
        print(f"{eco}:{count}:{engine}")


if __name__ == '__main__':
    main()
