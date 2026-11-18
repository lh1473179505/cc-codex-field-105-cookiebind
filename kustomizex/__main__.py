import argparse
from .audit import LegacyAudit
from .release import ReleasePipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="var/kustomizex")
    args = parser.parse_args()
    print(LegacyAudit(ReleasePipeline(args.root)).current())


if __name__ == "__main__":
    main()
