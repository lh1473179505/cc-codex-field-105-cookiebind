import sys
from .repro import main

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] != "repro":
        raise SystemExit("usage: python -m inotifyx repro")
    raise SystemExit(main())
