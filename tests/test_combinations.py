import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_restart_mixed_batch_and_retry(self):
        got = scenario()
        self.assertEqual(got["routes"], [(1, "initial"), (2, "new")])
        self.assertEqual(got["applied"], ["c1", "c3"])

if __name__ == "__main__":
    unittest.main()
