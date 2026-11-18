from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spnegox.diagnostics.trace import negotiation_trace
from spnegox.integration.routes import defect_probe
from spnegox.negotiation.machine import WORK_KEY
from spnegox.node.resume import resume_negotiations
from spnegox.integration.routes import ARTIFACT, AUTHORITY, CHANNELS, NEW_PAYLOAD, NEW_TX, OLD_PAYLOAD, OLD_TX, SOURCE, SUBJECT, TARGET, connect


class CombinedLifecycleRegression(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="spnegox-test-")
        self.work = Path(self.temporary.name)
        self.store, self.service = connect(self.work)

    def tearDown(self):
        self.temporary.cleanup()

    def begin(self):
        self.service.offer_negotiation(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
        self.service.stage_context(SOURCE, OLD_TX, OLD_PAYLOAD)

    def test_migration_then_second_stage_does_not_alias_or_cross_commit(self):
        self.begin()
        self.service.bridge_mechanism(SOURCE, TARGET, CHANNELS[1])
        self.service.stage_context(TARGET, NEW_TX, NEW_PAYLOAD)
        source_work = self.store.data["sessions"][SOURCE][WORK_KEY]
        target_work = self.store.data["sessions"][TARGET][WORK_KEY]
        self.assertEqual(OLD_TX, source_work["tx"])
        self.assertEqual(NEW_TX, target_work["tx"])
        self.assertIsNot(source_work, target_work)
        self.assertIsNot(source_work["payload"], target_work["payload"])
        self.assertIsNot(
            self.store.data["transactions"][OLD_TX]["payload"],
            self.store.data["transactions"][NEW_TX]["payload"],
        )
        target_work["payload"]["mutual"] = False
        self.assertTrue(source_work["payload"]["mutual"])
        self.assertEqual({"mech": "krb5", "mutual": False}, target_work["payload"])
        with self.assertRaises(PermissionError):
            self.service.establish_context(SOURCE, NEW_TX)

    def test_revocation_pins_inflight_but_rejects_new_work(self):
        self.begin()
        self.service.revoke_realm(AUTHORITY)
        self.assertEqual(1, self.store.data["transactions"][OLD_TX]["epoch"])
        self.assertEqual(2, self.store.epoch(AUTHORITY))
        self.assertEqual("committed", self.service.establish_context(SOURCE, OLD_TX)["status"])
        with self.assertRaises(PermissionError):
            self.service.stage_context(SOURCE, NEW_TX, NEW_PAYLOAD)

    def test_old_epoch_session_cannot_start_work_after_hand_off(self):
        self.begin()
        self.service.bridge_mechanism(SOURCE, TARGET, CHANNELS[1])
        self.service.revoke_realm(AUTHORITY)
        with self.assertRaises(PermissionError):
            self.service.stage_context(SOURCE, NEW_TX, NEW_PAYLOAD)
        with self.assertRaises(PermissionError):
            self.service.stage_context(TARGET, NEW_TX, NEW_PAYLOAD)

    def test_repro_reports_business_conclusions_without_expected_observed_diffs(self):
        report = defect_probe(self.work)
        self.assertEqual("ok", report["status"])
        self.assertNotIn("checks", report)
        self.assertNotIn("observed_mismatch", report)
        serialized = str(report)
        self.assertNotIn("expected", serialized)
        self.assertNotIn("observed", serialized)
        consistency = report["regression"]["online_offline_consistency"]
        self.assertEqual("match", consistency["conclusion"])
        self.assertEqual(consistency["online_digest"], consistency["offline_digest"])
        replay = report["regression"]["recovery_replay"]
        self.assertEqual(
            ["open", "stage", "migrate", "stage", "revoke", "commit"],
            replay["journal_order"],
        )
        self.assertTrue(replay["journal_seq_monotonic"])

    def test_readonly_audit_preserves_persistent_bytes(self):
        self.begin()
        before = self.store.state_path.read_bytes()
        first = negotiation_trace(self.store)
        second = negotiation_trace(self.store)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.state_path.read_bytes())

    def test_migrate_revoke_finish_and_replay_have_same_visible_state(self):
        self.begin()
        self.service.bridge_mechanism(SOURCE, TARGET, CHANNELS[1])
        self.service.revoke_realm(AUTHORITY)
        self.service.establish_context(SOURCE, OLD_TX)
        recovered_path = self.work / "recovered.json"
        recovered = resume_negotiations(self.store.journal_path, recovered_path)
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
