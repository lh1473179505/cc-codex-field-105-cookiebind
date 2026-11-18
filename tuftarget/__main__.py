import argparse
import json
from .client import LegacyTargetClient
from .release import TargetRelease


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="var/tuftarget")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    release = TargetRelease(args.root, {"targets": "targets-secret"})
    client = LegacyTargetClient(release)
    if args.list:
        print(json.dumps(client.listing()))


if __name__ == "__main__":
    main()
