import tempfile
import unittest
from corelimit.vault import Vault
from corelimit.capture import start, finish, SealFailure
from corelimit.cleaner import recover
from corelimit.usage import legacy_usage

class CombinationTests(unittest.TestCase):
    def test_failed_seal_recovery_releases_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            recover(vault)
            recover(vault)
            self.assertEqual(legacy_usage(vault)["used_bytes"], 0)

    def test_new_capture_respects_original_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            recover(vault)
            with self.assertRaises(MemoryError):
                start(vault, "core-8", 1024, "pay-api")

if __name__ == "__main__":
    unittest.main()
