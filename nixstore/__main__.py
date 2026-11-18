import argparse
from .bundle import LegacyBundle
from .recovery import StoreRecovery
from .release import StoreRelease


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("recover", "bundle"))
    parser.add_argument("--root", default="var/nixstore")
    args = parser.parse_args()
    release = StoreRelease(args.root)
    if args.command == "recover":
        StoreRecovery(release).reconcile()
    print(LegacyBundle(release).export())


if __name__ == "__main__":
    main()
