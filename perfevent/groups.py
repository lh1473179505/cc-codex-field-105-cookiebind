from . import group_state as states

class Groups:
    def __init__(self, counters):
        self.counters = counters
        self.items = {}
        self.intents = []
        self.epoch = 1

    def create(self, name, cpus):
        self.items[name] = {"state": states.DISARMED, "cpus": [], "requested": cpus,
                            "epoch": self.epoch, "cgroup": "pay"}

    def cancel(self, name):
        item = self.items[name]
        for cpu in list(item["cpus"]):
            self.counters.release(cpu)
        item["cpus"] = []
        item["state"] = states.CANCELLED
