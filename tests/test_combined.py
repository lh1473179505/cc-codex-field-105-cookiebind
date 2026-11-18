import json
import tempfile
import unittest

from tufrole.canonical import sign
from tufrole.roles import Role
from tufrole.service import RoleService
from tufrole.verifier import VerificationError


class EpochRecoveryTest(unittest.TestCase):
    def test_rotation_does_not_revoke_prepared_legacy_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=1)
            tx = service.begin(Role("root", 2, 1, signature))
            service.rotate(2, {"root": "root-two"}, {"root"})
            service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 2)

    def test_online_commit_after_rotation_uses_pinned_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=1)
            tx = service.begin(Role("root", 2, 1, signature))
            service.rotate(2, {"root": "root-two"}, {"root"})
            service.commit(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 2)

    def test_recovery_across_restart_uses_pinned_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=1)
            tx = service.begin(Role("root", 2, 1, signature))
            service.rotate(2, {"root": "root-two"}, {"root"})

            restarted = RoleService(tmp)
            restarted.recover(tx)
            self.assertEqual(restarted.snapshots.legacy()["roles"]["root"]["version"], 2)

    def test_failed_recovery_keeps_prior_snapshot_readable_and_retryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=1)
            tx = service.begin(Role("root", 2, 1, signature))
            service.rotate(2, {"root": "root-two"}, {"root"})

            record = service.transactions.load(tx)
            record["role"]["signature"] = "tampered"
            (service.transactions.root / (tx + ".json")).write_text(
                json.dumps(record, sort_keys=True)
            )

            with self.assertRaises(VerificationError):
                service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 1)
            self.assertEqual(service.transactions.load(tx)["state"], "prepared")

            record["role"]["signature"] = signature
            (service.transactions.root / (tx + ".json")).write_text(
                json.dumps(record, sort_keys=True)
            )
            service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 2)

    def test_new_transaction_cannot_reuse_revoked_predecessor_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            service.rotate(2, {"root": "root-two"}, {"root"})
            stale = sign("root", 3, 2, "root-one", envelope=1)
            tx = service.begin(Role("root", 3, 2, stale))
            with self.assertRaises(VerificationError):
                service.commit(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 1)

            fresh = sign("root", 3, 2, "root-two", envelope=1)
            tx_fresh = service.begin(Role("root", 3, 2, fresh))
            service.commit(tx_fresh)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 3)

    def test_legacy_snapshot_shape_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            self.assertEqual(
                service.snapshots.legacy(),
                {"format": 1, "roles": {"root": {"version": 1}}},
            )

    def test_envelope_two_commit_is_also_pinned_to_prepared_epoch(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            signature = sign("root", 2, 1, "root-one", envelope=2)
            tx = service.begin(Role("root", 2, 1, signature, envelope=2))
            service.rotate(2, {"root": "root-two"}, {"root"})
            service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 2)

    def test_revocation_at_pinned_epoch_still_rejects_prepared_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = RoleService(tmp)
            service.rotate(2, {"root": "root-two"}, {"root"})
            signature = sign("root", 3, 2, "root-two", envelope=1)
            tx = service.begin(Role("root", 3, 2, signature))
            service.rotate(3, {"root": "root-three"}, set())
            service.recover(tx)
            self.assertEqual(service.snapshots.legacy()["roles"]["root"]["version"], 3)

            stale = sign("root", 4, 3, "root-two", envelope=1)
            tx_stale = service.begin(Role("root", 4, 3, stale))
            with self.assertRaises(VerificationError):
                service.commit(tx_stale)


if __name__ == "__main__":
    unittest.main()
