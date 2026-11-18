import tempfile
import unittest

from tlskeylog.importer import recover
from tlskeylog.model import SessionState
from tlskeylog.secrets import traffic_secret
from tlskeylog.sessions import Service


class KeylogLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_handshake_retains_start_generation(self):
        self.service.open("tls-old")
        expected = traffic_secret(b"tls-master-key-v1", 1, "ab" * 32, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        self.service.rotate(b"tls-master-key-v2")
        self.assertEqual(self.service.finish_handshake("tls-old", "ab" * 32), expected)

    def test_read_only_audit_preserves_closed_session_and_files(self):
        self.service.open("tls-audit")
        self.service.finish_handshake("tls-audit", "cd" * 32)
        self.service.close("tls-audit")
        before = self.service.store.fingerprint()
        self.service.audit()
        self.assertEqual(self.service.sessions["tls-audit"].state, SessionState.CLOSED)
        self.assertTrue(self.service.sessions["tls-audit"].secrets)
        self.assertEqual(self.service.store.fingerprint(), before)

    def test_tls12_recovery_chain(self):
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "tls_session_opened", "identifier": "legacy"}])
        self.assertEqual(result["restored"], ["legacy"])
        self.assertTrue(result["tls12_client_random"])
