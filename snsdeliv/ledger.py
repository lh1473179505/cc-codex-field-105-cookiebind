class Ledger:
    def __init__(self):
        self.done = set()
        self.highwater = 0

    def plan(self, notices):
        batch = [n for n in sorted(notices, key=lambda n: n.seq) if n.key not in self.done]
        self.done.update(n.key for n in batch)
        if batch:
            self.highwater = max(self.highwater, max(n.seq for n in batch))
        return batch

    def export(self):
        return {"done": sorted(self.done), "highwater": self.highwater}
