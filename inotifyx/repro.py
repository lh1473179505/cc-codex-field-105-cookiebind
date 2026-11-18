import json
from .watches import Watches
from .queue import EventQueue
from .legacy_diag import snapshot
from .resync import recover_overflow

def main():
    watches = Watches()
    queue = EventQueue()
    queue.publish({"kind": "rename", "wd": 9, "to": "/srv/new"})
    diagnostic = snapshot(watches, queue)
    queue.overflow()
    recover_overflow(watches, queue)
    after = snapshot(watches, queue)
    stale = watches.by_wd[9]["path"] == "/srv/old"
    print(json.dumps({"diagnostic": diagnostic, "after_recovery": after,
                      "rename_lost_by_read": stale}, sort_keys=True))
    return 0 if stale and not diagnostic["pending"] == [] else 1
