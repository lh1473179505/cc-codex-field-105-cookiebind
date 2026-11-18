import tempfile
import unittest

from buildkit.exporter import CacheExporter, ExportError
from buildkit.reader import LegacyCacheReader
from buildkit.recovery import CacheRecovery


class CacheRecoveryTest(unittest.TestCase):
    def test_failed_reexport_does_not_collect_stable_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            exporter = CacheExporter(tmp)
            exporter.export("stable", ["shared-layer"])
            with self.assertRaises(ExportError):
                exporter.export("candidate", ["shared-layer", "new-layer"], "bad")
            CacheRecovery(exporter).collect()
            self.assertEqual(LegacyCacheReader(exporter).open("stable"), ["shared-layer"])


if __name__ == "__main__":
    unittest.main()
