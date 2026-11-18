"""Command-line entry points for batch execution and read-only audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .binder import ScanService


def execute(document: dict[str, object]) -> ScanService:
    service = ScanService()
    for operation in document["operations"]:
        kind = operation["type"]
        if kind == "snapshot":
            service.snapshot(generation=operation["generation"], sequence=operation["sequence"], rows=operation["rows"])
        elif kind == "delta":
            service.delta(action=operation.get("action", "delta"), key=operation["key"],
                          scope=operation.get("scope", "main"), fingerprint=operation["fingerprint"],
                          value=operation.get("value", ""), sequence=operation["sequence"])
        else:
            raise ValueError("unknown operation type: " + kind)
    return service


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kevbind")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "audit"):
        command = sub.add_parser(name)
        command.add_argument("document", type=Path)
    args = parser.parse_args(argv)
    document = json.loads(args.document.read_text(encoding="utf-8"))
    service = execute(document)
    output = service.report() if args.command == "run" else service.audit()
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0
