import unittest
from mtlsroute.audit import legacy_pairs, route_view
from mtlsroute.peers import Frame
from mtlsroute.router import Router

class Combination(unittest.TestCase):
    def test_rotate_fail_restore_same_contract(self):
        router = Router(fail={"poison"})
        token = router.open([Frame("s1", "edge-a", 1, "hello")])
        router.trust.rotate("edge-a", 2)
        with self.assertRaises(OSError):
            router.finish(token)
        with self.assertRaises(OSError):
            router.send([Frame("s2", "edge-b", 2, "poison")])
        self.assertNotIn("s1", router.ledger.accepted)
        self.assertNotIn("s2", router.ledger.accepted)
        router.wire.fail.clear()
        snap = router.snapshot()
        router.restore(snap)
        router.send([Frame("s2", "edge-b", 2, "poison")])
        view = route_view(router)
        self.assertEqual(view["wire"], [("edge-b", 2, "poison")])
        self.assertEqual(view["accepted"], ["s2"])
        self.assertEqual(legacy_pairs(router), [("edge-b", "poison")])

if __name__ == "__main__":
    unittest.main()
