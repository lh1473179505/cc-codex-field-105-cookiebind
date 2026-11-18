import tempfile
import unittest

from hpkebind.diagnostics import inspect
from hpkebind.sessions import Service
from hpkebind.suites import seal


class ContextIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_started_context_survives_recipient_rotation(self):
        self.service.start("s-old")
        expected = seal(b"recipient-private-key-v1", 1, "pay-hpke/v1", "pay:invoice:17", "invoice")
        self.service.rotate(b"recipient-private-key-v2")
        self.assertEqual(self.service.seal("s-old", "invoice"), expected)

    def test_oversize_failure_does_not_publish_partial_record(self):
        self.service.start("s-large")
        with self.assertRaises(ValueError):
            self.service.seal("s-large", "x" * 65)
        self.assertEqual(self.service.sessions["s-large"].records, [])
        self.assertEqual(self.service.store.events()[-1]["kind"], "context_started")

    def test_legacy_restore_and_diagnostics_are_stable(self):
        self.service.start("s-audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        from hpkebind.restore import recover
        result = recover(self.service, [{"kind": "context_started", "session": "v0"}])
        self.assertEqual(result["restored"], ["v0"])
        self.assertEqual(self.service.sessions["v0"].generation, 1)
