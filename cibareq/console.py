"""Command-line entry points for online operation, diagnostics and recovery."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from cibareq.ops.report import authentication_report
from cibareq.ops.replay import replay_authentication
from cibareq.flows.acceptance import defect_probe, online_demo
from cibareq.data.journal import JsonStore


def _with_work(argument, action) -> None:
    if argument:
        result = action(Path(argument))
    else:
        with tempfile.TemporaryDirectory(prefix="cibareq-") as temporary:
            result = action(Path(temporary))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cibareq")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "repro"):
        sub = commands.add_parser(name)
        sub.add_argument("--work")
    audit_parser = commands.add_parser("audit")
    audit_parser.add_argument("--state", required=True)
    recover_parser = commands.add_parser("recover")
    recover_parser.add_argument("--journal", required=True)
    recover_parser.add_argument("--state", required=True)
    args = parser.parse_args(argv)
    if args.command == "demo":
        _with_work(args.work, online_demo)
    elif args.command == "repro":
        _with_work(args.work, defect_probe)
    elif args.command == "audit":
        state = Path(args.state)
        store = JsonStore(state, state.with_suffix(".jsonl"))
        print(json.dumps(authentication_report(store), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        result = replay_authentication(Path(args.journal), Path(args.state))
        print(json.dumps({"sessions": sorted(result["sessions"]), "transactions": sorted(result["transactions"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
