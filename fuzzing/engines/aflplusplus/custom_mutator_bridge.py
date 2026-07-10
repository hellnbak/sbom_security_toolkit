#!/usr/bin/env python3
"""AFL++ custom mutator bridge scaffold.

AFL++ can import Python custom mutators when configured accordingly. This bridge
keeps mutation logic deterministic and delegates to the toolkit's mutator style.
"""
from __future__ import annotations
import json, random

def init(seed):
    random.seed(seed)

def fuzz(buf, add_buf, max_size):
    try:
        data=json.loads(bytes(buf).decode('utf-8','ignore') or '{}')
        if isinstance(data, dict):
            data.setdefault('metadata',{})['afl_custom_mutator']='sbom-security-toolkit'
            comps=data.get('components') or data.get('packages') or []
            if comps and isinstance(comps,list) and isinstance(comps[0],dict):
                comps[0]['version']='9.' + '9'*random.randint(1,16)
            out=json.dumps(data,separators=(',',':')).encode()
            return out[:max_size]
    except Exception:
        pass
    b=bytearray(buf)
    if b:
        b[random.randrange(len(b))] ^= 0x20
    return bytes(b[:max_size])

def deinit():
    pass
