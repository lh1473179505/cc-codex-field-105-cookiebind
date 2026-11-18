import tempfile
import unittest

from kanikox.bootstrap import BootstrapRecovery
from kanikox.compat import LegacyResolver
from kanikox.publisher import Publisher


class OrderedRecoveryTest(unittest.TestCase):
    def test_double_digit_sequence_does_not_move_tag_backwards(self):
        with tempfile.TemporaryDirectory() as tmp:
            publisher = Publisher(tmp)
            for number in range(10):
                latest = publisher.push("stable", {"version": str(number)})
            BootstrapRecovery(publisher).restore()
            self.assertEqual(LegacyResolver(publisher).snapshot()["stable"], latest)


if __name__ == "__main__":
    unittest.main()
