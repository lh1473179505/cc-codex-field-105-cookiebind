#!/usr/bin/env python3
"""Reproduce the baseline convergence defect; success means it is observable."""
from __future__ import annotations

import json
import sys

from cwegraph.graph_case import run_combination


def main() -> int:
    result = run_combination()
    print(json.dumps({
        "recovery": result["recovery"],
        "late": result["late"],
        "report": result["second"],
        "observed_problems": result["problems"],
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["problems"] else 1


if __name__ == "__main__":
    sys.exit(main())
