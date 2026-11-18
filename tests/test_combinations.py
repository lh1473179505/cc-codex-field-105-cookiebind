import unittest
from inotifyx.watches import Watches
from inotifyx.queue import EventQueue
from inotifyx.legacy_diag import snapshot
from inotifyx.consumer import pump
from inotifyx.resync import recover_overflow

class CombinationTests(unittest.TestCase):
    def test_snapshot_does_not_consume_pending_rename(self):
        watches = Watches()
        queue = EventQueue()
        queue.publish({"kind": "rename", "wd": 9, "to": "/srv/new"})
        snapshot(watches, queue)
        pump(watches, queue)
        self.assertEqual(watches.by_wd[9]["path"], "/srv/new")
        self.assertEqual(watches.paths["/srv/new"], 9)

    def test_overflow_followed_by_snapshot_is_safe(self):
        watches = Watches()
        queue = EventQueue()
        queue.overflow()
        before = queue.dropped
        snapshot(watches, queue)
        self.assertEqual(queue.dropped, before)

if __name__ == "__main__":
    unittest.main()
