import unittest
from provattest.artifact import Artifact
from provattest.service import Service
from provattest.verify import bundle_view, legacy_digests

class Combination(unittest.TestCase):
    def test_revoke_partial_seal_restore(self):
        svc = Service(fail={"d2"})
        token = svc.begin([
            Artifact("p1", "d1", "builder", 1),
            Artifact("p2", "d2", "promoter", 1),
        ])
        svc.policy.revoke_role("builder")
        with self.assertRaises(RuntimeError):
            svc.commit(token)
        self.assertEqual(svc.store.items, [])
        self.assertEqual(svc.attestor.granted, set())
        svc.store.fail.clear()
        snap = svc.snapshot()
        svc.restore(snap)
        svc.attest([Artifact("p2", "d2", "promoter", 2)])
        got = bundle_view(svc)
        self.assertEqual(got["sealed"], [("promoter", "d2")])
        self.assertEqual(got["granted"], ["p2"])
        self.assertEqual(legacy_digests(svc), ["d2"])

if __name__ == "__main__":
    unittest.main()
