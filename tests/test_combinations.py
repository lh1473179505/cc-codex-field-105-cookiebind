import tempfile
import unittest

from pkcs11op.hsmaudit import inspect
from pkcs11op.mechanisms import operate
from pkcs11op.model import TokenState
from pkcs11op.operations import Service
from pkcs11op.token_recovery import recover


class HsmOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)
        self.service.login(7)

    def tearDown(self):
        self.temp.cleanup()

    def test_open_operation_uses_original_key_generation(self):
        self.service.begin("op-old")
        self.service.rotate({"pay-sign-01": b"hsm-pay-sign-key-v2"})
        expected = operate(b"hsm-pay-sign-key-v1", "ECDSA_SHA256", "sign", b"message")
        self.assertEqual(self.service.finish("op-old", b"message"), expected)

    def test_mechanism_failure_can_abort_without_commit_residue(self):
        self.service.begin("op-retry")
        with self.assertRaises(ValueError):
            self.service.finish("op-retry", b"message", usage="decrypt")
        self.service.abort("op-retry")
        self.assertNotIn("op-retry", self.service.operations)
        self.assertEqual([e for e in self.service.store.events() if e["kind"] == "operation_committed"], [])
        self.service.begin("op-retry")
        self.assertEqual(self.service.operations["op-retry"].state, TokenState.OPERATION_OPEN)

    def test_legacy_recovery_and_read_only_audit(self):
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "token_logged_in", "slot": 7}, {"kind": "operation_started", "identifier": "legacy", "key_label": "pay-sign"}])
        self.assertEqual(result["legacy_label"], "pay-sign-01")
