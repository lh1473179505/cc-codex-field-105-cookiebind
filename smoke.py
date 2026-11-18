"""Baseline smoke: succeed only when the intended regressions reproduce cleanly."""
import subprocess
import sys
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    run = subprocess.run(command, cwd=root, text=True, capture_output=True)
    output = run.stdout + run.stderr
    expected = "FAILED (failures=2)"
    if run.returncode == 1 and expected in output and "errors=" not in output:
        print("baseline regressions reproduced; read-only and recovery contracts remain runnable")
        return 0
    print(output)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
