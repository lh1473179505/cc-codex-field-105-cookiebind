import json
import tempfile
import unittest
from pathlib import Path

from jsonnetx.legacy import LegacyOutput
from jsonnetx.pipeline import RenderPipeline, RenderError


class RollbackCompatibilityTest(unittest.TestCase):
    def test_failed_second_output_restores_existing_legacy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "legacy").mkdir()
            (root / "legacy" / "report.json").write_text("old-report")
            pipeline = RenderPipeline(root)
            closure_digest, closure = pipeline.closures.freeze({"lib": {"x": 1}})
            _, manifest = pipeline.evaluator.evaluate(closure, {"legacy/report.json": "new", "z/last.json": "last"})
            good = pipeline.token({"legacy/report.json": manifest["legacy/report.json"]}, 1)
            with self.assertRaises(RenderError):
                pipeline.publish({"lib": {"x": 1}}, {"legacy/report.json": "new", "z/last.json": "last"}, signatures={"legacy/report.json": good})
            self.assertEqual(LegacyOutput(root).read("legacy/report.json"), "old-report")


if __name__ == "__main__":
    unittest.main()
