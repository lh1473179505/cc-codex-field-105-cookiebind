from . import session_states as states

class Sessions:
    def __init__(self, targets, registry):
        self.targets = targets
        self.registry = registry
        self.items = {}
        self.epoch = {}
        self.serial = 0

    def attach(self, namespace, pid, fail_thread=None):
        self.serial += 1
        sid = "trace-%d" % self.serial
        item = {"namespace": namespace, "pid": pid, "threads": [],
                "state": states.ATTACHING, "epoch": self.epoch.get(namespace, 0)}
        self.items[sid] = item
        try:
            for thread in self.targets.items[namespace][pid]["threads"]:
                if thread == fail_thread:
                    raise OSError("thread vanished")
                item["threads"].append(thread)
            item["state"] = states.BOUND
            self.registry.bind(namespace, pid, sid)
            return sid
        except OSError:
            item["threads"] = []
            item["state"] = states.CLOSED
            raise

    def detach(self, sid):
        item = self.items[sid]
        item["state"] = states.DETACHING
        self.registry.unbind(item["namespace"], item["pid"], sid)
        item["threads"] = []
        item["state"] = states.CLOSED

    def revoke(self, namespace):
        self.epoch[namespace] = self.epoch.get(namespace, 0) + 1
