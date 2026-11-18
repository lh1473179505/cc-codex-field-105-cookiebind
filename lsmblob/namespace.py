from . import lifecycle

def migrate(store, hooks, operation, destination):
    lease = hooks.inflight[operation]
    name = lease["name"]
    store.phase[name] = lifecycle.MIGRATING
    store.namespace[name] = destination
    store.phase[name] = lifecycle.ATTACHED
