class Registry:
    def __init__(self):
        # Original single-namespace index retained for fast legacy lookup.
        self.by_pid = {}

    def bind(self, namespace, pid, session):
        self.by_pid[pid] = (namespace, session)

    def unbind(self, namespace, pid, session):
        self.by_pid.pop(pid, None)

    def resolve(self, namespace, pid):
        item = self.by_pid.get(pid)
        if item is None or item[0] != namespace:
            return None
        return item[1]
