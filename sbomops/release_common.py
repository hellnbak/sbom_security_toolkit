from __future__ import annotations
import datetime as dt, hashlib, json, os, tempfile
from pathlib import Path
from typing import Any
try:
    import yaml
except Exception:
    yaml = None

def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')

def load_data(path: str|Path|None, default: Any=None) -> Any:
    if not path: return default
    p=Path(path)
    if not p.exists(): return default
    text=p.read_text(encoding='utf-8')
    if p.suffix.lower() in {'.yml', '.yaml'}:
        if yaml is None:
            raise RuntimeError(
                f'Cannot read YAML file {p}: PyYAML is not installed. '
                'Run python -m pip install -e ".[dev]" or install PyYAML.'
            )
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f'Invalid JSON in {p}: {exc}') from exc

def atomic_write(path: str|Path, text: str) -> Path:
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=p.name+'.', dir=p.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(text)
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return p

def write_json(path: str|Path, obj: Any) -> Path:
    return atomic_write(path, json.dumps(obj,indent=2,sort_keys=True)+'\n')

def write_yaml(path: str|Path, obj: Any) -> Path:
    if yaml:
        return atomic_write(path, yaml.safe_dump(obj,sort_keys=False))
    return write_json(path,obj)

def sha256(path: str|Path) -> str:
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def parse_time(value: str|None):
    if not value: return None
    try: return dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    except Exception: return None
