from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SeparateCommandChains(unittest.TestCase):
    def test_online_cli_diagnostics_and_replay(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="scimprov-cli-") as temporary:
            work = Path(temporary)
            demo = subprocess.run(
                [sys.executable, "-m", "scimprov", "demo", "--work", str(work)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, demo.returncode, demo.stderr)
            self.assertIn("digest", json.loads(demo.stdout))
            state = work / "state.json"
            before = state.read_bytes()
            report = subprocess.run(
                [sys.executable, "-m", "scimprov", "audit", "--state", str(state)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, report.returncode, report.stderr)
            self.assertEqual(before, state.read_bytes())
            restored = subprocess.run(
                [sys.executable, "-m", "scimprov", "recover", "--journal", str(work / "journal.jsonl"), "--state", str(work / "restored.json")],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, restored.returncode, restored.stderr)
            self.assertIn(SOURCE := "scimprov-source", json.loads(restored.stdout)["sessions"])


if __name__ == "__main__":
    unittest.main()
