import tempfile
import unittest
from keyringx.rings import Rings
from keyringx.transfer import begin, abort, resume, TransferCrash
from keyringx.leases import revoke
from keyringx.startup import recover
from keyringx.legacy_audit import key_audit
from keyringx import operation

class CombinationTests(unittest.TestCase):
    def test_recovery_uses_original_lease_after_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            with self.assertRaises(TransferCrash):
                begin(rings, 101, "pay-source", "pay-dest", crash=True)
            revoke(rings, 101)
            self.assertEqual(recover(rings), {})
            self.assertNotIn(101, rings.data["rings"]["pay-source"])
            self.assertEqual(rings.data["rings"]["pay-dest"], [101])
            self.assertEqual(rings.data["operations"]["move-1"]["state"],
                             operation.COMMITTED)
            self.assertEqual(rings.data["operations"]["move-1"]["epoch"], 3)

    def test_repeated_recovery_is_idempotent_and_location_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            with self.assertRaises(TransferCrash):
                begin(rings, 101, "pay-source", "pay-dest", crash=True)
            revoke(rings, 101)
            self.assertEqual(recover(rings), {})
            self.assertEqual(recover(rings), {})
            view = key_audit(rings)
            self.assertEqual(view["locations"]["101"], ["pay-dest"])
            self.assertEqual(view["operations"], [
                {"id": "move-1", "state": operation.COMMITTED, "epoch": 3}])

    def test_revocation_blocks_new_transfer_but_keeps_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            with self.assertRaises(TransferCrash):
                begin(rings, 101, "pay-source", "pay-dest", crash=True)
            revoke(rings, 101)
            with self.assertRaises(PermissionError):
                begin(rings, 101, "pay-source", "pay-dest")
            self.assertEqual(rings.data["serial"], 1)
            self.assertEqual(set(rings.data["operations"]), {"move-1"})
            self.assertEqual(recover(rings), {})
            self.assertEqual(rings.data["rings"]["pay-dest"], [101])

    def test_revocation_blocks_new_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            revoke(rings, 101)
            rings.data["epochs"][101] += 0
            self.assertEqual(rings.data["epochs"][101], 4)
            with self.assertRaises(PermissionError):
                begin(rings, 101, "pay-source", "pay-dest")

    def test_abort_rolls_back_linked_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            with self.assertRaises(TransferCrash):
                begin(rings, 101, "pay-source", "pay-dest", crash=True)
            abort(rings, "move-1")
            self.assertEqual(rings.data["rings"]["pay-source"], [101])
            self.assertEqual(rings.data["rings"]["pay-dest"], [])
            self.assertEqual(rings.data["operations"]["move-1"]["state"],
                             operation.ABORTED)
            view = key_audit(rings)
            self.assertEqual(view["locations"]["101"], ["pay-source"])

    def test_normal_transfer_commits_without_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            opid = begin(rings, 101, "pay-source", "pay-dest")
            self.assertEqual(opid, "move-1")
            self.assertEqual(rings.data["rings"]["pay-source"], [])
            self.assertEqual(rings.data["rings"]["pay-dest"], [101])
            self.assertEqual(rings.data["operations"][opid]["state"],
                             operation.COMMITTED)
            self.assertEqual(recover(rings), {})

    def test_resume_rejects_stale_lease_on_public_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            with self.assertRaises(TransferCrash):
                begin(rings, 101, "pay-source", "pay-dest", crash=True)
            revoke(rings, 101)
            with self.assertRaises(PermissionError):
                resume(rings, "move-1")
            self.assertEqual(rings.data["operations"]["move-1"]["state"],
                             operation.LINKED)

if __name__ == "__main__":
    unittest.main()
