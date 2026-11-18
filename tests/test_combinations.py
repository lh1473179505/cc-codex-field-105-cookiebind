import unittest
from spiffewire.channel import Packet
from spiffewire.export import audit_rows, summary
from spiffewire.gateway import Gateway

class Combination(unittest.TestCase):
    def test_migrate_partial_fail_restore(self):
        gw = Gateway(fail={"x"})
        token = gw.begin([
            Packet("a1", "spiffe://prod.example/api", 1, "ok"),
            Packet("a2", "spiffe://prod.example/worker", 1, "x"),
        ])
        gw.bundle.migrate("edge.example", ["spiffe://edge.example/api"])
        with self.assertRaises(RuntimeError):
            gw.commit(token)
        self.assertEqual(gw.channel.sent, [])
        self.assertEqual(gw.window.done, set())
        snap = gw.snapshot()
        gw.restore(snap)
        gw.channel.fail.clear()
        gw.publish([Packet("b1", "spiffe://edge.example/api", 2, "ok2")])
        summ = summary(gw)
        self.assertEqual(summ["sent"], ["b1"])
        self.assertEqual(summ["done"], ["b1"])
        self.assertEqual(summ["domain"], "edge.example")
        self.assertEqual(audit_rows(gw)[0]["domain"], "edge.example")

if __name__ == "__main__":
    unittest.main()
