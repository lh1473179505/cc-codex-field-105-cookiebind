class Checkpoint:
    def __init__(self):
        self.offset = 0

    def advance(self, batch):
        if batch:
            self.offset = max(self.offset, max(e.seq for e in batch))

    def export(self):
        return {"offset": self.offset}
