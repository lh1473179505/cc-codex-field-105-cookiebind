import json
import tempfile
import unittest

from jwezip.consumer import recover
from jwezip.jweaudit import inspect
from jwezip.producer import Service


class JweTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_issued_token_retains_original_content_key(self):
        self.service.issue("jwt-old")
        self.service.append("jwt-old", b"invoice")
        self.service.rotate(b"jwe-content-key-v2")
        token = self.service.seal("jwt-old")
        self.assertEqual(json.loads(token["protected"])["kid"], "key-1")

    def test_abort_releases_buffer_before_identifier_reuse(self):
        self.service.issue("jwt-reuse")
        self.service.append("jwt-reuse", b"stale")
        self.service.abort("jwt-reuse")
        self.service.issue("jwt-reuse")
        token = self.service.seal("jwt-reuse")
        import zlib
        self.assertEqual(zlib.decompress(bytes.fromhex(token["ciphertext"])), b"")

    def test_json_recovery_and_read_only_audit(self):
        self.service.issue("jwt-audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "token_issued", "identifier": "legacy"}])
        self.assertEqual(result["legacy_empty"], "")
