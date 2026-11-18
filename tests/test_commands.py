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
        with tempfile.TemporaryDirectory(prefix="devicecode-cli-") as temporary:
            work = Path(temporary)
            demo = subprocess.run(
                [sys.executable, "-m", "devicecode", "demo", "--work", str(work)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, demo.returncode, demo.stderr)
            self.assertIn("digest", json.loads(demo.stdout))
            state = work / "state.json"
            before = state.read_bytes()
            report = subprocess.run(
                [sys.executable, "-m", "devicecode", "audit", "--state", str(state)],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, report.returncode, report.stderr)
            self.assertEqual(before, state.read_bytes())
            self.assertEqual({"sessions", "pending", "digest"}, set(json.loads(report.stdout)))
            restored = subprocess.run(
                [sys.executable, "-m", "devicecode", "recover", "--journal", str(work / "journal.jsonl"), "--state", str(work / "restored.json")],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, restored.returncode, restored.stderr)
            self.assertIn("devicecode-source", json.loads(restored.stdout)["sessions"])

    def test_repro_cli_reports_status_without_observed_diffs(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="devicecode-repro-") as temporary:
            probe = subprocess.run(
                [sys.executable, "-m", "devicecode", "repro", "--work", str(Path(temporary))],
                cwd=root, capture_output=True, text=True, check=False,
            )
            self.assertEqual(0, probe.returncode, probe.stderr)
            report = json.loads(probe.stdout)
            self.assertEqual("all_invariants_hold", report["status"])
            self.assertNotIn("observed_mismatch", report)
            self.assertEqual(report["online_digest"], report["offline_digest"])


if __name__ == "__main__":
    unittest.main()
