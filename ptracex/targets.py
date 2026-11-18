class Targets:
    def __init__(self):
        self.items = {"alpha": {7: {"threads": [70, 71]}},
                      "beta": {7: {"threads": [70, 71]}}}

    def move(self, source, destination, pid):
        self.items[destination][pid] = self.items[source].pop(pid)
