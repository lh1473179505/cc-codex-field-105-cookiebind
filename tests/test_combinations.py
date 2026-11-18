import tempfile
import unittest

from cmsenv.content import content_key, unwrap
from cmsenv.enveloper import Service
from cmsenv.envelopes import EnvelopeState
from cmsenv.reports import inspect
from cmsenv.unseal import recover


class EnvelopePhaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_existing_recipient_is_not_rewrapped_after_rotation(self):
        self.service.begin("env-old", b"invoice")
        self.service.add_recipient("env-old", "alice")
        self.service.rotate({"alice": b"alice-cms-v2"})
        result = self.service.seal("env-old")
        cek = content_key("env-old", b"invoice")
        self.assertTrue(unwrap(cek, b"alice-cms-v1", "alice", 1, result["wrapped"]["alice"]))

    def test_unknown_recipient_leaves_no_partial_membership(self):
        self.service.begin("env-fail", b"invoice")
        with self.assertRaises(ValueError):
            self.service.add_recipient("env-fail", "mallory")
        envelope = self.service.envelopes["env-fail"]
        self.assertEqual(envelope.recipients, [])
        self.assertEqual(envelope.state, EnvelopeState.COLLECTING)

    def test_unseal_restore_and_reporting(self):
        self.service.begin("env-audit", b"audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "envelope_started", "identifier": "legacy"}])
        self.assertEqual(result["restored"], ["legacy"])
