import argparse
from .builder import Builder
from .inspect import LegacyInspect
from .recover import BuildRecovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("recover", "inspect"))
    parser.add_argument("--root", default="var/buildahx")
    args = parser.parse_args()
    builder = Builder(args.root)
    if args.command == "recover":
        BuildRecovery(builder).replay()
    print(LegacyInspect(builder).image())


if __name__ == "__main__":
    main()
