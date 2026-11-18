import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_late_failure_replay_and_audit(self):
        got = scenario()
        self.assertEqual(got["values"], ["alpha", "beta"])
        self.assertEqual(got["offset"], 2)
        self.assertEqual(got["pending"], [])

if __name__ == "__main__":
    unittest.main()
