from __future__ import annotations
import argparse, json, sys
from datetime import datetime, timezone
from pathlib import Path
from .engine import admit_ticket, inspect_ticket
from .load import load_json, load_nonce_store, save_nonce_store

def parse_now(s: str) -> int:
    if s.isdigit():
        return int(s)
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tickpac")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_i = sub.add_parser("inspect"); p_i.add_argument("--ticket", required=True)
    p_a = sub.add_parser("admit")
    p_a.add_argument("--ticket", required=True)
    p_a.add_argument("--keys", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--nonce-store", required=True)
    p_a.add_argument("--now", required=True)
    p_a.add_argument("--report", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "inspect":
        print(json.dumps(inspect_ticket(load_json(args.ticket)), ensure_ascii=False, indent=2))
        return 0
    try:
        ticket = load_json(args.ticket)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_nonce_store(args.nonce_store)
        now = parse_now(args.now)
        report = admit_ticket(ticket, keys, policy, store, now)
    except ValueError as e:
        print(str(e), file=sys.stderr); return 2
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if report.get("decision") == "allow":
        save_nonce_store(args.nonce_store, store); return 0
    if report.get("decision") == "deny":
        return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
