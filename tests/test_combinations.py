import tempfile
import unittest
from corelimit.vault import Vault
from corelimit.capture import start, finish, SealFailure
from corelimit.cleaner import recover
from corelimit.revoke import revoke_owner
from corelimit.usage import legacy_usage


def assert_conserved(test_case, vault):
    view = legacy_usage(vault)
    test_case.assertGreaterEqual(view["used_bytes"], 0)
    test_case.assertEqual(view["used_bytes"],
                          sum(view["reservations"].values()))
    return view

class CombinationTests(unittest.TestCase):
    def test_failed_seal_recovery_releases_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            assert_conserved(self, vault)
            recover(vault)
            recover(vault)
            view = assert_conserved(self, vault)
            self.assertEqual(view["used_bytes"], 0)
            self.assertEqual(view["reservations"], {})
            self.assertEqual(view["states"], {"core-7": "aborted"})

    def test_new_capture_respects_original_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            recover(vault)
            with self.assertRaises(MemoryError):
                start(vault, "core-8", 1024, "pay-api")

    def test_recovery_resumes_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            self.assertEqual(legacy_usage(vault)["used_bytes"], 0)

            resumed = Vault(tmp)
            self.assertEqual(legacy_usage(resumed)["states"],
                             {"core-7": "aborted"})
            self.assertEqual(recover(resumed), ["core-7"])
            self.assertEqual(recover(Vault(tmp)), [])
            self.assertEqual(legacy_usage(Vault(tmp))["used_bytes"], 0)

    def test_ledger_conserved_through_repeated_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-a", 300, "pay-api")
            start(vault, "core-b", 200, "billing")
            with self.assertRaises(SealFailure):
                finish(vault, "core-a", fail=True)
            for _ in range(5):
                recover(vault)
                view = assert_conserved(self, vault)
            self.assertEqual(view["used_bytes"], 200)
            self.assertEqual(view["reservations"], {"core-b": 200})

    def test_revocation_blocks_new_but_allows_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            revoke_owner(vault, "pay-api")
            with self.assertRaises(PermissionError):
                start(vault, "core-8", 64, "pay-api")
            with self.assertRaises(SealFailure):
                finish(vault, "core-7", fail=True)
            self.assertEqual(recover(vault), ["core-7"])
            self.assertEqual(legacy_usage(vault)["used_bytes"], 0)

    def test_successful_seal_releases_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Vault(tmp)
            start(vault, "core-7", 256, "pay-api")
            finish(vault, "core-7")
            view = assert_conserved(self, vault)
            self.assertEqual(view["used_bytes"], 0)
            self.assertEqual(recover(vault), [])

if __name__ == "__main__":
    unittest.main()
