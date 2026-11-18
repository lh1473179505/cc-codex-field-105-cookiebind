import base64
import json
import os
import tempfile
import unittest

from rfc3161.archiver import recover
from rfc3161.observer import inspect
from rfc3161.tokens import TokenState
from rfc3161.timestamper import Service


def response(identifier, payload, nonce):
    import hashlib
    value = {"id": identifier, "imprint": hashlib.sha256(payload).hexdigest(), "nonce": nonce}
    return base64.b64encode(json.dumps(value).encode()).decode()


class TimestampRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_outstanding_request_keeps_original_tsa_generation(self):
        self.service.request("ts-old", b"release", "pay-0123456789abcdef")
        self.service.rotate_tsa("tsa-pay-cert-v2")
        self.service.accept("ts-old", response("ts-old", b"release", "pay-0123456789abcdef"))
        self.assertEqual(self.service.archive("ts-old")["generation"], 1)

    def test_malformed_response_does_not_burn_retry_nonce(self):
        self.service.request("ts-retry", b"release", "pay-retry-0001")
        with self.assertRaises(ValueError):
            self.service.accept("ts-retry", "not-base64")
        self.assertNotIn("pay-retry-0001", self.service.consumed_nonces)
        self.service.pending.pop("ts-retry")
        self.service.request("ts-retry", b"release", "pay-retry-0001")

    def test_archive_restore_and_read_only_observer(self):
        self.service.request("ts-audit", b"audit", "pay-audit-0001")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "timestamp_requested", "identifier": "v0", "nonce": "n"}])
        self.assertEqual(result["restored"], ["v0"])

    def test_nonce_is_consumed_only_after_successful_verification(self):
        nonce = "pay-nonce-lifecycle"
        self.service.request("ts-life", b"release", nonce)
        self.assertNotIn(nonce, self.service.consumed_nonces)
        with self.assertRaises(ValueError):
            self.service.accept("ts-life", "not-base64")
        self.assertNotIn(nonce, self.service.consumed_nonces)
        self.service.accept("ts-life", response("ts-life", b"release", nonce))
        self.assertIn(nonce, self.service.consumed_nonces)
        with self.assertRaises(ValueError):
            self.service.request("ts-life-copy", b"release", nonce)

    def test_late_response_retry_and_archive_restore_keep_trust_chain(self):
        self.service.request("ts-old", b"release", "pay-0123456789abcdef")
        self.service.rotate_tsa("tsa-pay-cert-v2")
        with self.assertRaises(ValueError):
            self.service.accept("ts-old", "corrupted-frame")
        archived = self.service.archive("ts-old") if False else None
        value = self.service.accept("ts-old", response("ts-old", b"release", "pay-0123456789abcdef"))
        self.assertEqual(value["nonce"], "pay-0123456789abcdef")
        archived = self.service.archive("ts-old")
        self.assertEqual(archived["generation"], 1)

        rebuilt = Service(self.temp.name + "/restored")
        result = recover(rebuilt, self.service.store.events())
        self.assertEqual(result["restored"], ["ts-old"])
        token = rebuilt.pending["ts-old"]
        self.assertEqual(token.state, TokenState.ARCHIVED)
        self.assertEqual(token.tsa_generation, 1)
        self.assertEqual(token.imprint, archived["imprint"])
        self.assertEqual(rebuilt.generation, 2)

    def test_observer_has_no_filesystem_side_effects(self):
        missing = os.path.join(self.temp.name, "never-created")
        view = inspect(missing)
        self.assertFalse(os.path.exists(missing))
        self.assertEqual(view["event_count"], 0)
        self.assertEqual(view["audit_count"], 0)
