#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REVIEW = ROOT / "ai_fuzz" / "review"


def queue_path(state: str) -> Path:
    p = REVIEW / state
    p.mkdir(parents=True, exist_ok=True)
    return p


def list_items() -> int:
    for state in ["incoming", "accepted", "rejected"]:
        print(f"\n[{state}]")
        items = sorted(x for x in queue_path(state).glob("*") if not x.name.startswith("."))
        if not items:
            print("  (empty)")
        for item in items:
            print(f"  {item.name}")
    return 0


def move_item(name: str, dest_state: str) -> int:
    src = None
    for state in ["incoming", "accepted", "rejected"]:
        candidate = queue_path(state) / name
        if candidate.exists():
            src = candidate
            break
    if src is None:
        raise SystemExit(f"Not found in review queues: {name}")
    dest = queue_path(dest_state) / src.name
    if dest.exists():
        shutil.rmtree(dest) if dest.is_dir() else dest.unlink()
    shutil.move(str(src), str(dest))
    print(f"Moved {name} -> {dest_state}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Manage AI fuzzing review queue.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    for cmd in ["accept", "reject"]:
        p = sub.add_parser(cmd)
        p.add_argument("name")
    args = ap.parse_args()
    if args.cmd == "list":
        return list_items()
    return move_item(args.name, "accepted" if args.cmd == "accept" else "rejected")

if __name__ == "__main__":
    raise SystemExit(main())
