#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, shutil
from pathlib import Path
from .ui import main as ui_main

# Thin wrapper retained for a stable command name. It aggregates report JSON into data.json
# and then invokes the existing static HTML generator.
def collect(base: Path):
    data = {}
    for p in base.rglob("*.json"):
        try:
            data[str(p.relative_to(base))] = json.loads(p.read_text())
        except Exception:
            pass
    return data

def main():
    ap = argparse.ArgumentParser(description="Build a local static UI bundle with data.json.")
    ap.add_argument("--reports-dir", default="reports"); ap.add_argument("--out-dir", default="reports/ui")
    args = ap.parse_args()
    base = Path(args.reports_dir); out = Path(args.out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "data.json").write_text(json.dumps(collect(base), indent=2) + "\n", encoding="utf-8")
    # call through subprocess-style to avoid refactoring ui.py parser
    import sys
    old = sys.argv[:]
    try:
        sys.argv = ["ui", "--reports-dir", str(base), "--out", str(out / "index.html")]
        ui_main()
    finally:
        sys.argv = old
    print(out)
if __name__ == "__main__": main()
