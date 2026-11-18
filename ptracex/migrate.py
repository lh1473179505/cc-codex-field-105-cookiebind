from . import session_states as states

def migrate(sessions, sid, destination):
    item = sessions.items[sid]
    source = item["namespace"]
    sessions.targets.move(source, destination, item["pid"])
    item["state"] = states.MIGRATING
    item["namespace"] = destination
    # Routing is rebuilt lazily by the next attach rather than at migration.
    item["state"] = states.BOUND
