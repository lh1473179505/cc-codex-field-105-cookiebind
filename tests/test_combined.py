import tempfile
import unittest
from pathlib import Path

from aclgrant.paths import (
    ARTIFACT,
    AUTHORITY,
    CHANNELS,
    NEW_PAYLOAD,
    NEW_TX,
    OLD_PAYLOAD,
    OLD_TX,
    SOURCE,
    SUBJECT,
    TARGET,
    connect,
)
from aclgrant.recover import replay
from aclgrant.view import diagnose


class Combined(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="aclgrant-test-")
        self.work = Path(self.temporary.name)
        self.store, self.service = connect(self.work)

    def tearDown(self):
        self.temporary.cleanup()

    def begin(self):
        self.service.prepare(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
        self.service.stage(SOURCE, OLD_TX, OLD_PAYLOAD)

    def test_handover_does_not_alias_work_or_cursor(self):
        self.begin()
        self.service.move(SOURCE, TARGET, CHANNELS[1])
        self.service.stage(TARGET, NEW_TX, NEW_PAYLOAD)
        self.assertEqual(OLD_TX, self.store.data["sessions"][SOURCE]["work"]["tx"])
        self.assertEqual(NEW_TX, self.store.data["sessions"][TARGET]["work"]["tx"])
        self.assertEqual([1], self.store.data["cursors"][self.store.data["sessions"][SOURCE]["cursor_id"]])
        self.assertEqual([9], self.store.data["cursors"][self.store.data["sessions"][TARGET]["cursor_id"]])
        with self.assertRaises(PermissionError):
            self.service.commit(SOURCE, NEW_TX)

    def test_revoke_pins_inflight_and_rejects_new_stage(self):
        self.begin()
        self.service.revoke(AUTHORITY)
        self.assertEqual("committed", self.service.commit(SOURCE, OLD_TX)["status"])
        with self.assertRaises(PermissionError):
            self.service.stage(SOURCE, NEW_TX, NEW_PAYLOAD)

    def test_audit_does_not_rewrite_bytes(self):
        self.begin()
        before = self.store.state_path.read_bytes()
        first = diagnose(self.store)
        second = diagnose(self.store)
        self.assertEqual(first, second)
        self.assertEqual(before, self.store.state_path.read_bytes())

    def test_replay_matches_online_after_handover_and_revoke(self):
        self.begin()
        self.service.move(SOURCE, TARGET, CHANNELS[1])
        self.service.revoke(AUTHORITY)
        self.service.commit(SOURCE, OLD_TX)
        recovered = replay(self.store.journal_path, self.work / "recovered.json")
        self.assertEqual(
            {key: value["phase"] for key, value in self.store.data["sessions"].items()},
            {key: value["phase"] for key, value in recovered["sessions"].items()},
        )
        self.assertEqual(
            {key: value["status"] for key, value in self.store.data["transactions"].items()},
            {key: value["status"] for key, value in recovered["transactions"].items()},
        )
        self.assertEqual(
            self.store.data["cursors"][self.store.data["sessions"][SOURCE]["cursor_id"]],
            recovered["cursors"][recovered["sessions"][SOURCE]["cursor_id"]],
        )


if __name__ == "__main__":
    unittest.main()
