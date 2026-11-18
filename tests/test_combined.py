import tempfile
import unittest

from tufrole.canonical import sign
from tufrole.roles import Role
from tufrole.service import RoleService


class EpochRecoveryTest(unittest.TestCase):
    def test_rotation_does_not_revoke_prepared_legacy_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=1)
            tx = service.begin(Role("root", 2, 1, signature))
            service.rotate(2, {"root": "root-two"}, {"root"})
            service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 2)


if __name__ == "__main__":
    unittest.main()
