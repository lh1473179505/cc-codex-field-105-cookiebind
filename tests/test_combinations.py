import unittest
from sarifgate.model import Finding
from sarifgate.pipeline import Pipeline
from sarifgate.report import board, sarif_results

class Combination(unittest.TestCase):
    def test_quarantine_partial_index_restore(self):
        pipe = Pipeline(fail={"dead"})
        token = pipe.begin([
            Finding("f1", "CWE-79", "error", 1, "abc"),
            Finding("f2", "CWE-89", "error", 1, "dead"),
        ])
        pipe.rules.revoke("CWE-79")
        with self.assertRaises(IOError):
            pipe.commit(token)
        self.assertEqual(pipe.index.rows, [])
        self.assertEqual(pipe.inbox.published, set())
        pipe.index.fail.clear()
        snap = pipe.snapshot()
        pipe.restore(snap)
        pipe.submit([Finding("f2", "CWE-89", "error", 2, "dead")])
        got = board(pipe)
        self.assertEqual(got["findings"], [("CWE-89", "error")])
        self.assertEqual(got["published"], ["f2"])
        self.assertEqual(sarif_results(pipe)[0]["ruleId"], "CWE-89")

if __name__ == "__main__":
    unittest.main()
