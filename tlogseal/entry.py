import argparse
import json
import tempfile
from pathlib import Path

from tlogseal.paths import defect_probe, online_demo
from tlogseal.recover import replay
from tlogseal.store import JsonStore
from tlogseal.view import diagnose


def _with_work(argument, action) -> None:
    if argument:
        result = action(Path(argument))
    else:
        with tempfile.TemporaryDirectory(prefix="tlogseal-") as temporary:
            result = action(Path(temporary))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="tlogseal")
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
        print(json.dumps(diagnose(store), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        result = replay(Path(args.journal), Path(args.state))
        print(json.dumps({"sessions": sorted(result["sessions"]), "transactions": sorted(result["transactions"])}, sort_keys=True))
    return 0
