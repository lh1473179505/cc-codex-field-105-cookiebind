import argparse
from .bootstrap import BootstrapRecovery
from .compat import LegacyResolver
from .publisher import Publisher


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("restore", "resolve"))
    parser.add_argument("--root", default="var/kanikox")
    parser.add_argument("--tag", default="stable")
    args = parser.parse_args()
    publisher = Publisher(args.root)
    if args.command == "restore":
        BootstrapRecovery(publisher).restore()
    print(LegacyResolver(publisher).resolve(args.tag))


if __name__ == "__main__":
    main()
