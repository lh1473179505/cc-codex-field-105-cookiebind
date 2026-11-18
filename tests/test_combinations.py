import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_reorder_write_failure_and_migration(self):
        original, migrated = scenario()
        self.assertEqual(original["delivered"], {7: 0})
        self.assertEqual(migrated["payloads"], [(7, b"abcd")])

if __name__ == "__main__":
    unittest.main()
