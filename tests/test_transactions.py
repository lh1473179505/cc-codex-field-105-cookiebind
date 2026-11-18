import copy
import tempfile
import unittest

from sysctlsec.database import Database
from sysctlsec.writer import change, InterruptedWrite
from sysctlsec.reboot import recover, untracked_runtime_writes
from sysctlsec.diagnostics import legacy_view
from sysctlsec.namespaces import migrate
from sysctlsec import machine


class TransactionTests(unittest.TestCase):
    def _db(self):
        db = Database(tempfile.mkdtemp())
        db.data["active"]["boot-1"] = 4
        return db

    def test_intent_durable_before_runtime_change(self):
        db = self._db()
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        self.assertEqual(len(db.data["intents"]), 1)
        intent = db.data["intents"][0]
        self.assertEqual(intent["status"], machine.RUNTIME_WRITTEN)
        self.assertEqual(intent["before_runtime"], 2)
        self.assertEqual(intent["before_persistent"], 2)
        self.assertEqual(intent["value"], 0)
        self.assertEqual(intent["epoch"], 4)
        self.assertEqual(db.data["runtime"]["kernel"]["kernel.randomize_va_space"], 0)
        self.assertEqual(db.data["persistent"]["kernel"]["kernel.randomize_va_space"], 2)

    def test_recovery_rolls_back_runtime_written_with_original_epoch(self):
        db = self._db()
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        recovered = recover(db)
        intent = db.data["intents"][0]
        self.assertEqual(recovered, ["boot-1"])
        self.assertEqual(intent["status"], machine.ABORTED)
        self.assertEqual(intent["epoch"], 4)
        self.assertEqual(db.data["epoch"], 4)
        self.assertEqual(db.data["runtime"]["kernel"]["kernel.randomize_va_space"], 2)
        self.assertEqual(db.data["persistent"]["kernel"]["kernel.randomize_va_space"], 2)
        self.assertEqual(untracked_runtime_writes(db), [])

    def test_recovery_does_not_require_fresh_permission_grant(self):
        db = self._db()
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        db.data["active"].clear()
        recovered = recover(db)
        self.assertEqual(recovered, ["boot-1"])
        self.assertTrue(legacy_view(db)["settings"][0]["consistent"])

    def test_proposed_intent_is_aborted_on_recovery(self):
        db = self._db()
        from sysctlsec.intent import record
        item = record(db, "kernel", "kernel.randomize_va_space", 1, "boot-1")
        self.assertEqual(item["status"], machine.PROPOSED)
        recover(db)
        self.assertEqual(item["status"], machine.ABORTED)
        self.assertEqual(untracked_runtime_writes(db), [])

    def test_orphan_runtime_write_is_reverted_to_durable_value(self):
        db = self._db()
        db.data["runtime"]["kernel"]["kernel.randomize_va_space"] = 0
        db.save()
        self.assertEqual(len(untracked_runtime_writes(db)), 1)
        recover(db)
        self.assertEqual(db.data["runtime"]["kernel"]["kernel.randomize_va_space"], 2)
        self.assertEqual(untracked_runtime_writes(db), [])

    def test_clean_commit_keeps_runtime_and_persistent_aligned(self):
        db = self._db()
        item = change(db, "kernel", "kernel.randomize_va_space", 0)
        self.assertEqual(item["status"], machine.COMMITTED)
        self.assertEqual(recover(db), [])
        view = legacy_view(db)
        self.assertEqual(view["pending"], 0)
        self.assertTrue(all(row["consistent"] for row in view["settings"]))

    def test_legacy_view_shape_and_fields_are_preserved(self):
        db = self._db()
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        before = copy.deepcopy(db.data)
        view = legacy_view(db)
        self.assertEqual(set(view), {"settings", "pending"})
        self.assertEqual(view["pending"], 1)
        row = view["settings"][0]
        self.assertEqual(set(row),
                         {"key", "namespace", "runtime", "persistent", "consistent"})
        self.assertEqual(row["namespace"], "kernel")
        self.assertFalse(row["consistent"])
        self.assertEqual(db.data, before)

    def test_migration_carries_intent_lineage_and_recovery_still_works(self):
        db = self._db()
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        db.data["runtime"].setdefault("hardened", {})
        db.data["persistent"].setdefault("hardened", {})
        migrate(db, "kernel", "hardened", "kernel.randomize_va_space")
        intent = db.data["intents"][0]
        self.assertEqual(intent["namespace"], "hardened")
        self.assertEqual(intent["key"], "kernel.randomize_va_space")
        self.assertEqual(intent["before_runtime"], 2)
        self.assertEqual(intent["epoch"], 4)
        recover(db)
        view = legacy_view(db)
        migrated = next(row for row in view["settings"]
                        if row["key"] == "kernel.randomize_va_space")
        self.assertEqual(migrated["namespace"], "hardened")
        self.assertTrue(migrated["consistent"])
        self.assertEqual(migrated["runtime"], 2)
        self.assertEqual(untracked_runtime_writes(db), [])

    def test_repeated_interruptions_remain_verifiable_transactions(self):
        db = self._db()
        change(db, "kernel", "kernel.randomize_va_space", 1)
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        recover(db)
        self.assertEqual(len(db.data["intents"]), 2)
        self.assertEqual([item["epoch"] for item in db.data["intents"]], [4, 4])
        self.assertEqual(
            db.data["runtime"]["kernel"]["kernel.randomize_va_space"], 1)
        self.assertEqual(
            db.data["persistent"]["kernel"]["kernel.randomize_va_space"], 1)
        self.assertEqual(untracked_runtime_writes(db), [])

    def test_reboot_uses_fresh_database_instance_and_pending_record(self):
        tmp = tempfile.mkdtemp()
        db = Database(tmp)
        db.data["active"]["boot-1"] = 4
        with self.assertRaises(InterruptedWrite):
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)

        rebooted = Database(tmp)
        self.assertEqual(
            rebooted.data["runtime"]["kernel"]["kernel.randomize_va_space"], 0)
        self.assertEqual(
            rebooted.data["intents"][0]["status"], machine.RUNTIME_WRITTEN)
        recover(rebooted)
        row = legacy_view(rebooted)["settings"][0]
        self.assertTrue(row["consistent"])
        self.assertEqual(row["runtime"], 2)
        self.assertEqual(rebooted.data["epoch"], 4)
        self.assertEqual(untracked_runtime_writes(rebooted), [])


if __name__ == "__main__":
    unittest.main()
