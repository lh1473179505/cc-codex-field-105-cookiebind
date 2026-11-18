import tempfile
import unittest

from tuftarget.client import LegacyTargetClient
from tuftarget.delegation import signature
from tuftarget.release import TargetRelease, DelegationError


class TargetTransactionTest(unittest.TestCase):
    def test_second_delegation_failure_does_not_leak_first_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = TargetRelease(tmp, {"targets": "secret"})
            client = LegacyTargetClient(release)
            with self.assertRaises(DelegationError):
                release.publish([
                    {"path": "app", "target": {"role": "targets", "bytes": 1}, "role": "targets", "signature": "bad"},
                ], 1)
            self.assertEqual(client.listing(), [])
            self.assertEqual(release.plan.generation(), 0)


if __name__ == "__main__":
    unittest.main()
