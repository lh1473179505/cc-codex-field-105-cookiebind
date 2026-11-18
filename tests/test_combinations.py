import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_migration_failure_and_capture(self):
        original, restored = scenario()
        self.assertEqual(original["messages"], [])
        self.assertEqual(original["completed"], [])
        self.assertEqual(restored["completed"], [])

if __name__ == "__main__":
    unittest.main()
