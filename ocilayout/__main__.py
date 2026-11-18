import argparse
from .consumer import LegacyLayout
from .release import LayoutRelease


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="var/ocilayout")
    args = parser.parse_args()
    release = LayoutRelease(args.root)
    print(LegacyLayout(release).platforms())


if __name__ == "__main__":
    main()
