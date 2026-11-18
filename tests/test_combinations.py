import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_channel_barrier_failure_snapshot(self):
        original, restored = scenario()
        self.assertEqual(original["rows"], [("news", 1, "first"), ("news", 2, "second")])
        self.assertEqual(original["handled"], ["one", "two"])
        self.assertEqual(restored["rows"], [])

if __name__ == "__main__":
    unittest.main()
