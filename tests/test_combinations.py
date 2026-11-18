import tempfile
import unittest
from fanotify.broker import Broker
from fanotify.dispatcher import open_permission, respond
from fanotify.subscriptions import revoke, drained
from fanotify.audit import legacy_audit

class CombinationTests(unittest.TestCase):
    def test_revocation_only_blocks_new_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker = Broker(tmp)
            event = open_permission(broker, "scan", "/srv/pay/a")
            revoke(broker, "scan")
            self.assertEqual(respond(broker, event, True), "allow")
            self.assertTrue(drained(broker, "scan"))
            with self.assertRaises(PermissionError):
                open_permission(broker, "scan", "/srv/pay/b")

    def test_one_event_has_one_terminal_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            broker = Broker(tmp)
            event = open_permission(broker, "scan", "/srv/pay/a")
            respond(broker, event, False)
            self.assertEqual(len(legacy_audit(broker)["decisions"]), 1)

if __name__ == "__main__":
    unittest.main()
