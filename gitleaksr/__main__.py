from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from .engine import admit_gitleaks_rule, inspect_gitleaks_rule
from .load import load_json, load_store, save_store

def parse_now(s: str) -> int:
    if s.isdigit():
        return int(s)
    from datetime import datetime
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m gitleaksr")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_i = sub.add_parser("inspect"); p_i.add_argument("--gitleaks-rule", required=True)
    p_a = sub.add_parser("admit")
    p_a.add_argument("--gitleaks-rule", required=True)
    p_a.add_argument("--keys", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--store", required=True)
    p_a.add_argument("--now", required=True)
    p_a.add_argument("--report", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "inspect":
        print(json.dumps(inspect_gitleaks_rule(load_json(args.gitleaks_rule)), ensure_ascii=False, indent=2)); return 0
    try:
        obj = load_json(args.gitleaks_rule)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_store(args.store)
        report = admit_gitleaks_rule(obj, keys, policy, store, parse_now(args.now))
    except ValueError as e:
        print(str(e), file=sys.stderr); return 2
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    if report.get("decision")=="allow":
        save_store(args.store, store); return 0
    if report.get("decision")=="deny":
        return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
