"""Command-line operator entry point; recovery is intentionally a separate chain."""
import argparse
import json
from pathlib import Path

from xmlenc.documents import Service
from xmlenc.stream import recover
from xmlenc.xmlreport import inspect


def main(argv=None):
    parser = argparse.ArgumentParser(prog="xmlenc")
    parser.add_argument("command", choices=("audit", "recover"))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--input")
    args = parser.parse_args(argv)
    if args.command == "audit":
        result = inspect(args.workspace)
    else:
        if not args.input:
            parser.error("recover requires --input")
        events = [json.loads(line) for line in Path(args.input).read_text(encoding="utf-8").splitlines() if line]
        result = recover(Service(args.workspace), events)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
