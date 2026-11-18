import base64
import json
import tempfile
import unittest

from rfc3161.archiver import recover
from rfc3161.observer import inspect
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
