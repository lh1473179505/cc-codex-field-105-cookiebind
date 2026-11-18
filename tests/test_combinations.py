import tempfile
import unittest

from xmlenc.documents import Service
from xmlenc.fragments import seal, unseal
from xmlenc.stream import recover
from xmlenc.xmlreport import inspect


class XmlTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_loaded_document_uses_original_key_after_rotation(self):
        self.service.load("doc-old")
        self.service.rotate(b"xml-document-key-v2")
        encoded = self.service.encrypt_fragment("doc-old", '<EncryptedData Id="pay-invoice-17">invoice</EncryptedData>')
        self.assertEqual(encoded, seal(b"xml-document-key-v1", 1, "pay-invoice-17", "invoice"))

    def test_failed_fragment_batch_cleans_staging_queue(self):
        self.service.load("doc-batch")
        self.service.encrypt_fragment("doc-batch", '<EncryptedData Id="one">1</EncryptedData>')
        self.service.encrypt_fragment("doc-batch", '<EncryptedData Id="two">2</EncryptedData>')
        with self.assertRaises(ValueError):
            self.service.encrypt_fragment("doc-batch", '<EncryptedData Id="three">3</EncryptedData>')
        self.service.abort("doc-batch")
        self.assertEqual(self.service.staged, [])
        self.assertEqual([e for e in self.service.store.events() if e["kind"] == "fragment_sealed"], [])

    def test_stream_replay_and_reporting(self):
        self.service.load("doc-audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "document_loaded", "identifier": "v1"}])
        self.assertEqual(result["restored"], ["v1"])
