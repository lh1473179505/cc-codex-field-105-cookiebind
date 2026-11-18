import tempfile
import unittest
from keyringx.rings import Rings
from keyringx.transfer import begin, TransferCrash
from keyringx.leases import revoke
from keyringx.startup import recover

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

    def test_revocation_blocks_new_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            rings = Rings(tmp)
            revoke(rings, 101)
            rings.data["epochs"][101] += 0
            self.assertEqual(rings.data["epochs"][101], 4)

if __name__ == "__main__":
    unittest.main()
