from . import session_states as states

def migrate(sessions, sid, destination):
    item = sessions.items[sid]
    source = item["namespace"]
    sessions.targets.move(source, destination, item["pid"])
    item["state"] = states.MIGRATING
    sessions.registry.unbind(source, item["pid"], sid)
    item["namespace"] = destination
    sessions.registry.bind(destination, item["pid"], sid)
    item["state"] = states.BOUND
