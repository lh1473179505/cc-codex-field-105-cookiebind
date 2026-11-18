class Registry:
    def __init__(self):
        # Routing identity is the (namespace, pid) pair; a pid alone is not unique.
        self.by_route = {}

    def bind(self, namespace, pid, session):
        self.by_route[(namespace, pid)] = session

    def unbind(self, namespace, pid, session):
        key = (namespace, pid)
        # Only the session that owns the binding may remove it; a stale
        # session cleaning up must not unbind a newer session on the same pid.
        if self.by_route.get(key) == session:
            del self.by_route[key]

    def resolve(self, namespace, pid):
        return self.by_route.get((namespace, pid))
