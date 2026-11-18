import unittest
from reproduce import scenario

class Combination(unittest.TestCase):
    def test_partial_fanout_then_replay(self):
        got = scenario()
        self.assertEqual(got["rows"], {"a": ["one", "two"], "b": ["one", "two"]})
        self.assertEqual(got["highwater"], 2)

if __name__ == "__main__":
    unittest.main()
