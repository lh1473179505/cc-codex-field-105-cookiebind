import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_reset_reuse_partial_flush_retry(self):
        got = scenario()
        self.assertEqual(got["rows"], [(2, 3, "new-headers")])
        self.assertEqual(got["sent"], {3: 11})

if __name__ == "__main__":
    unittest.main()
