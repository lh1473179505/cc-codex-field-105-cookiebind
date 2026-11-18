import tempfile
import unittest

from nixstore.bundle import LegacyBundle
from nixstore.recovery import StoreRecovery
from nixstore.release import StoreRelease, StoreError


class ClosureRecoveryTest(unittest.TestCase):
    def test_failed_generation_leaves_no_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = StoreRelease(tmp)
            values = [{"name": "app", "value": 1}, {"name": "bad", "value": 2}]
            signatures = {"app": release.signer.signature(release.nar.add(values[0])[0], 1)}
            with self.assertRaises(StoreError):
                release.publish(values, signatures, 1)
            StoreRecovery(release).reconcile()
            self.assertEqual(LegacyBundle(release).export()["entries"], [])


if __name__ == "__main__":
    unittest.main()
