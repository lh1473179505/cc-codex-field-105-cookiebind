import tempfile
import unittest

from dsseenv.attestaudit import inspect
from dsseenv.offline import recover
from dsseenv.signing import sign
from dsseenv.threshold import Service


class ThresholdRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_draft_accepts_original_signer_after_rotation(self):
        self.service.draft("release-old", b"release")
        self.service.rotate({"alice": b"alice-dsse-v2", "amy": b"amy-dsse-v2"})
        expected = sign(b"alice-dsse-v1", "application/vnd.pay.release+json", b"release")
        self.assertEqual(self.service.add_signature("release-old", "alice"), expected)

    def test_failed_signature_does_not_reserve_signer(self):
        self.service.draft("release-retry", b"release")
        with self.assertRaises(ValueError):
            self.service.add_signature("release-retry", "mallory")
        self.assertEqual(self.service.attestations["release-retry"].signatures, [])
        self.service.add_signature("release-retry", "alice")

    def test_offline_alias_and_read_only_projection(self):
        self.service.draft("release-audit", b"audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "attestation_drafted", "identifier": "legacy"}])
        self.assertTrue(result["legacy_type"].endswith("+json"))
