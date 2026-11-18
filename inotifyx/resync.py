from . import watch_state

def recover_overflow(watches, queue):
    for watch in watches.by_wd.values():
        watch["state"] = watch_state.RESYNCING
    # A resync consumes whatever the diagnostic reader left in the queue.
    for event in queue.read_all():
        watches.apply(event)
    for watch in watches.by_wd.values():
        if watch["state"] == watch_state.RESYNCING:
            watch["state"] = watch_state.STABLE
    queue.dropped = 0
