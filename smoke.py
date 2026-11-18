"""Smoke check: the multi-stage timestamp recovery chain must stay green."""
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    run = subprocess.run(command, cwd=root, text=True, capture_output=True)
    output = run.stdout + run.stderr
    if run.returncode == 0 and "OK" in output:
        print("generation pinning, nonce retry, archive recovery and read-only audit all pass")
        return 0
    print(output)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
