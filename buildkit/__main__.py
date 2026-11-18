import argparse
from .exporter import CacheExporter
from .reader import LegacyCacheReader
from .recovery import CacheRecovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("gc", "inspect"))
    parser.add_argument("--root", default="var/buildkit")
    parser.add_argument("--name", default="stable")
    args = parser.parse_args()
    exporter = CacheExporter(args.root)
    if args.command == "gc":
        CacheRecovery(exporter).collect()
    else:
        print(LegacyCacheReader(exporter).inspect(args.name))


if __name__ == "__main__":
    main()
