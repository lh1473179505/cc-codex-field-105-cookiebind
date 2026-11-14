from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import admit_plan, inspect_plan
from .load import load_json

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m idnapin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_i = sub.add_parser("inspect"); p_i.add_argument("--plan", required=True)
    p_a = sub.add_parser("admit")
    p_a.add_argument("--plan", required=True)
    p_a.add_argument("--keys", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--report", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "inspect":
        print(json.dumps(inspect_plan(load_json(args.plan)), ensure_ascii=False, indent=2)); return 0
    try:
        report = admit_plan(load_json(args.plan), load_json(args.keys), load_json(args.policy))
    except ValueError as e:
        print(str(e), file=sys.stderr); return 2
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    if report.get("decision")=="allow": return 0
    if report.get("decision")=="deny": return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
