class Hooks:
    def __init__(self, store):
        self.store = store
        self.inflight = {}

    def begin(self, operation, name):
        self.inflight[operation] = {"name": name, "view": self.store.view(name),
                                    "namespace": self.store.namespace[name]}
        return self.inflight[operation]

    def decision(self, operation):
        view = self.inflight[operation]["view"]
        return bytes(view).decode("ascii")
