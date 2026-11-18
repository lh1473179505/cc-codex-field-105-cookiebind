import tempfile
import unittest
from pathlib import Path

from hkdfkey.inspector import inspect
from hkdfkey.kdf import derive
from hkdfkey.rotation import Service


class RotationCombinationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_rotation_leaves_started_transaction_on_original_epoch(self):
        self.service.begin("tx-old")
        expected = derive(b"original-master-key-2026", "pay/api/v1")
        self.service.rotate(b"replacement-master-key-2026")
        self.assertEqual(self.service.commit("tx-old", "pay/api/v1"), expected)

    def test_rejected_rotation_is_atomic(self):
        with self.assertRaises(ValueError):
            self.service.rotate(b"short")
        self.assertEqual(self.service.active, 1)
        self.assertNotIn(2, self.service.epochs)

    def test_read_only_diagnostics_and_legacy_replay(self):
        self.service.begin("tx-audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        from hkdfkey.replay import recover
        other = Service(Path(self.temp.name) / "recovery")
        result = recover(other, [{"kind": "derivation_started", "identifier": "legacy", "epoch": 1}])
        self.assertEqual(result["resumed"], ["legacy"])
        self.assertEqual(len(result["legacy_v0_digest"]), 64)
