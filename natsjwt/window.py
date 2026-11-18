class BarrierWindow:
    def __init__(self):
        self.pending = {}
        self.seen = set()
        self.watermark = 0

    def accept(self, event):
        if event.key in self.seen or event.seq < self.watermark:
            return []
        self.seen.add(event.key)
        self.watermark = max(self.watermark, event.seq)
        self.pending[event.seq] = event
        if event.seq != event.barrier:
            return []
        batch = [self.pending[k] for k in sorted(self.pending)]
        self.pending.clear()
        return batch

    def restore(self, state):
        self.seen = set(state["seen"])
        self.watermark = state["watermark"]
