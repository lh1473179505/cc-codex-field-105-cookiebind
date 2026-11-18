import argparse
from pathlib import Path

from .audit import LegacyAudit
from .service import LogService


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("recover", "audit"))
    parser.add_argument("--root", default="var/rekorlog")
    args = parser.parse_args()
    service = LogService(Path(args.root), {"publisher": "local-secret"})
    service.recover()
    if args.command == "audit":
        print(LegacyAudit(service).export())


if __name__ == "__main__":
    main()
