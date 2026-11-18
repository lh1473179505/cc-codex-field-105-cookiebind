from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from oidclogout.compliance.view import logout_audit
from oidclogout.logout.machine import WORK_KEY
from oidclogout.state.resume import resume_logout
from oidclogout.acceptance.scenario import ARTIFACT, AUTHORITY, CHANNELS, NEW_PAYLOAD, NEW_TX, OLD_PAYLOAD, OLD_TX, SOURCE, SUBJECT, TARGET, connect


class CombinedLifecycleRegression(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="oidclogout-test-")
        self.work = Path(self.temporary.name)
        self.store, self.service = connect(self.work)

    def tearDown(self):
        self.temporary.cleanup()

    def begin(self):
        self.service.announce_logout(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
        self.service.prepare_delivery(SOURCE, OLD_TX, OLD_PAYLOAD)

    def test_migration_then_second_stage_does_not_alias_or_cross_commit(self):
        self.begin()
        self.service.switch_backchannel(SOURCE, TARGET, CHANNELS[1])
        self.service.prepare_delivery(TARGET, NEW_TX, NEW_PAYLOAD)
        self.assertEqual(OLD_TX, self.store.data["sessions"][SOURCE][WORK_KEY]["tx"])
        self.assertEqual(NEW_TX, self.store.data["sessions"][TARGET][WORK_KEY]["tx"])
        with self.assertRaises(PermissionError):
            self.service.finish_logout(SOURCE, NEW_TX)

    def test_revocation_pins_inflight_but_rejects_new_work(self):
        self.begin()
        self.service.revoke_relying_party(AUTHORITY)
        self.assertEqual("committed", self.service.finish_logout(SOURCE, OLD_TX)["status"])
        with self.assertRaises(PermissionError):
            self.service.prepare_delivery(SOURCE, NEW_TX, NEW_PAYLOAD)

    def test_readonly_audit_preserves_persistent_bytes(self):
        self.begin()
        before = self.store.state_path.read_bytes()
        first = logout_audit(self.store)
        second = logout_audit(self.store)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.state_path.read_bytes())

    def test_migrate_revoke_finish_and_replay_have_same_visible_state(self):
        self.begin()
        self.service.switch_backchannel(SOURCE, TARGET, CHANNELS[1])
        self.service.revoke_relying_party(AUTHORITY)
        self.service.finish_logout(SOURCE, OLD_TX)
        recovered_path = self.work / "recovered.json"
        recovered = resume_logout(self.store.journal_path, recovered_path)
        self.assertEqual(
            {key: value["phase"] for key, value in self.store.data["sessions"].items()},
            {key: value["phase"] for key, value in recovered["sessions"].items()},
        )
        self.assertEqual(
            {key: value["status"] for key, value in self.store.data["transactions"].items()},
            {key: value["status"] for key, value in recovered["transactions"].items()},
        )


if __name__ == "__main__":
    unittest.main()
