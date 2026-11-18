#!/usr/bin/env python3
"""Run the end-to-end convergence scenario; exits non-zero if any problem is observed."""
from __future__ import annotations

import json
import sys

from trivyconf.mixed_case import run_combination


def main() -> int:
    result = run_combination()
    print(json.dumps({
        "recovery": result["recovery"],
        "late": result["late"],
        "report": result["second"],
        "observed_problems": result["problems"],
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if result["problems"] else 0


if __name__ == "__main__":
    sys.exit(main())
