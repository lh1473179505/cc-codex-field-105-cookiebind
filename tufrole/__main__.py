import argparse
from .service import RoleService


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("snapshot", "recover"))
    parser.add_argument("--root", default="var/tufrole")
    parser.add_argument("--tx")
    args = parser.parse_args()
    service = RoleService(args.root)
    if args.command == "recover":
        service.recover(args.tx)
    print(service.snapshots.legacy())


if __name__ == "__main__":
    main()
