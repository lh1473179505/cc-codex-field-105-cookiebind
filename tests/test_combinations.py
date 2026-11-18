import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_revoke_failure_and_replay(self):
        got = scenario()
        self.assertEqual(got["rows"], [(2, "bad")])
        self.assertEqual(got["done"], ["new"])

if __name__ == "__main__":
    unittest.main()
