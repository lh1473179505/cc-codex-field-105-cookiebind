import unittest
from ptracex.targets import Targets
from ptracex.registry import Registry
from ptracex.sessions import Sessions
from ptracex.migrate import migrate
from ptracex.daemon import lookup

class CombinationTests(unittest.TestCase):
    def test_old_detach_cannot_unbind_new_namespace_session(self):
        sessions = Sessions(Targets(), Registry())
        old = sessions.attach("alpha", 7)
        migrate(sessions, old, "beta")
        new = sessions.attach("beta", 7)
        sessions.detach(old)
        self.assertIsNotNone(lookup(sessions, "beta", 7))
        self.assertEqual(lookup(sessions, "beta", 7)["state"], "bound")

    def test_revoked_namespace_still_detaches_existing_session(self):
        sessions = Sessions(Targets(), Registry())
        sid = sessions.attach("alpha", 7)
        sessions.revoke("alpha")
        sessions.detach(sid)
        self.assertEqual(sessions.items[sid]["state"], "closed")

if __name__ == "__main__":
    unittest.main()
