import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_partial_delete_restore_and_timeout(self):
        original, restored = scenario()
        self.assertEqual(original["states"]["b"], "inflight")
        self.assertEqual(restored["states"]["b"], "inflight")

if __name__ == "__main__":
    unittest.main()
