import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_failed_send_revoke_and_resume(self):
        original, resumed = scenario()
        self.assertEqual(original["rows"], [("e1", "old")])
        self.assertEqual(original["last_sequence"], 1)
        self.assertEqual(resumed["last_sequence"], 1)

if __name__ == "__main__":
    unittest.main()
