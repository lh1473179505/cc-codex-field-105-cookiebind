import argparse
from .legacy import LegacyOutput


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="var/jsonnetx")
    parser.add_argument("--output", default="legacy/report.json")
    args = parser.parse_args()
    print(LegacyOutput(args.root).read(args.output))


if __name__ == "__main__":
    main()
