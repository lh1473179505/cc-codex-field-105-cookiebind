import tempfile
import unittest

from minisign.artifact_recovery import recover
from minisign.model import ReleaseState
from minisign.publisher import Service
from minisign.releaseaudit import inspect
from minisign.signature import artifact_signature


class ArtifactLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Service(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_loaded_artifact_keeps_original_signing_key(self):
        self.service.load("pay-release.tar", b"artifact")
        self.service.rotate(b"minisign-release-key-v2")
        expected = artifact_signature(b"minisign-release-key-v1", "pay-release.tar", b"artifact", "timestamp:2026-06-18 artifact:pay-release")
        self.assertEqual(self.service.sign("pay-release.tar"), expected)

    def test_partial_dual_signature_failure_rolls_back(self):
        self.service.load("pay-release.tar", b"artifact")
        with self.assertRaises(ValueError):
            self.service.sign("pay-release.tar", fail_after=True)
        artifact = self.service.artifacts["pay-release.tar"]
        self.assertEqual(artifact.signatures, [])
        self.assertEqual(artifact.state, ReleaseState.LOADED)
        self.assertEqual([e for e in self.service.store.events() if e["kind"] == "artifact_signed"], [])

    def test_legacy_recovery_and_read_only_audit(self):
        self.service.load("pay-release.tar", b"audit")
        before = self.service.store.fingerprint()
        inspect(self.temp.name)
        self.assertEqual(self.service.store.fingerprint(), before)
        result = recover(Service(self.temp.name + "/copy"), [{"kind": "artifact_loaded", "identifier": "legacy"}])
        self.assertIn("artifact:legacy", result["comment"])
