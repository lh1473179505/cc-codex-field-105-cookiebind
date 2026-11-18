from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from devicecode.monitor import device_status
from devicecode.model import WORK_KEY
from devicecode.rebuild import rebuild_devices
from devicecode.usecases import ARTIFACT, AUTHORITY, CHANNELS, NEW_PAYLOAD, NEW_TX, OLD_PAYLOAD, OLD_TX, SOURCE, SUBJECT, TARGET, connect, defect_probe


class CombinedLifecycleRegression(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="devicecode-test-")
        self.work = Path(self.temporary.name)
        self.store, self.service = connect(self.work)

    def tearDown(self):
        self.temporary.cleanup()

    def begin(self):
        self.service.open_device(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
        self.service.stage_verification(SOURCE, OLD_TX, OLD_PAYLOAD)

    def test_migration_then_second_stage_does_not_alias_or_cross_commit(self):
        self.begin()
        self.service.companion_takeover(SOURCE, TARGET, CHANNELS[1])
        self.service.stage_verification(TARGET, NEW_TX, NEW_PAYLOAD)
        source_work = self.store.data["sessions"][SOURCE][WORK_KEY]
        target_work = self.store.data["sessions"][TARGET][WORK_KEY]
        self.assertEqual(OLD_TX, source_work["tx"])
        self.assertEqual(NEW_TX, target_work["tx"])
        self.assertIsNot(source_work, target_work)
        self.assertIsNot(source_work["payload"], target_work["payload"])
        self.assertEqual(OLD_PAYLOAD, source_work["payload"])
        self.assertEqual(NEW_PAYLOAD, target_work["payload"])
        source_work["payload"]["attempt"] = 99
        self.assertEqual(2, target_work["payload"]["attempt"])
        with self.assertRaises(PermissionError):
            self.service.redeem_code(SOURCE, NEW_TX)
        with self.assertRaises(PermissionError):
            self.service.redeem_code(TARGET, OLD_TX)

    def test_revocation_pins_inflight_but_rejects_new_work(self):
        self.begin()
        self.service.revoke_device_client(AUTHORITY)
        with self.assertRaises(PermissionError):
            self.service.stage_verification(SOURCE, NEW_TX, NEW_PAYLOAD)
        self.assertEqual("committed", self.service.redeem_code(SOURCE, OLD_TX)["status"])

    def test_inflight_commit_is_rejected_from_any_other_session(self):
        self.begin()
        self.service.companion_takeover(SOURCE, TARGET, CHANNELS[1])
        with self.assertRaises(PermissionError):
            self.service.redeem_code(TARGET, OLD_TX)
        self.assertEqual("pending", self.store.data["transactions"][OLD_TX]["status"])

    def test_readonly_audit_preserves_persistent_bytes(self):
        self.begin()
        before = self.store.state_path.read_bytes()
        first = device_status(self.store)
        second = device_status(self.store)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.state_path.read_bytes())

    def test_migrate_revoke_finish_and_replay_have_same_visible_state(self):
        self.begin()
        self.service.companion_takeover(SOURCE, TARGET, CHANNELS[1])
        self.service.revoke_device_client(AUTHORITY)
        self.service.redeem_code(SOURCE, OLD_TX)
        recovered_path = self.work / "recovered.json"
        recovered = rebuild_devices(self.store.journal_path, recovered_path)
        self.assertEqual(
            {key: value["phase"] for key, value in self.store.data["sessions"].items()},
            {key: value["phase"] for key, value in recovered["sessions"].items()},
        )
        self.assertEqual(
            {key: value["status"] for key, value in self.store.data["transactions"].items()},
            {key: value["status"] for key, value in recovered["transactions"].items()},
        )

    def test_repro_reports_invariants_without_expected_observed_diffs(self):
        report = defect_probe(self.work)
        self.assertEqual("all_invariants_hold", report["status"])
        self.assertNotIn("checks", report)
        self.assertNotIn("observed_mismatch", report)
        self.assertEqual(
            {
                "migration_work_independent": True,
                "cross_session_commit": "rejected",
                "in_flight_after_revoke": "committed",
                "stale_sessions_blocked": True,
                "audit_read_only": True,
                "online_offline_same_conclusion": True,
            },
            report["invariants"],
        )
        self.assertEqual(report["online_digest"], report["offline_digest"])


if __name__ == "__main__":
    unittest.main()
