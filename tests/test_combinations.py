import copy
import tempfile
import unittest
from sysctlsec.database import Database
from sysctlsec.writer import change, InterruptedWrite
from sysctlsec.reboot import recover
from sysctlsec.diagnostics import legacy_view

class CombinationTests(unittest.TestCase):
    def test_interruption_never_leaves_untracked_runtime_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(tmp)
            db.data["active"]["boot-1"] = 4
            with self.assertRaises(InterruptedWrite):
                change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
            recover(db)
            row = legacy_view(db)["settings"][0]
            self.assertTrue(row["consistent"])
            self.assertEqual(row["runtime"], 2)

    def test_diagnostic_has_no_transaction_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(tmp)
            before = copy.deepcopy(db.data)
            legacy_view(db)
            self.assertEqual(db.data, before)

if __name__ == "__main__":
    unittest.main()
