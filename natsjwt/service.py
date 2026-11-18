from .checkpoint import Checkpoint
from .events import Sink
from .snapshot import Snapshot
from .window import BarrierWindow

class Service:
    def __init__(self, fail=()):
        self.window = BarrierWindow()
        self.checkpoint = Checkpoint()
        self.sink = Sink(fail)

    def ingest(self, event):
        batch = self.window.accept(event)
        self.checkpoint.advance(batch)
        for item in batch:
            self.sink.write(item)
        return [e.key for e in batch]

    def recover(self, state, tail):
        Snapshot.restore(self.window, self.checkpoint, state)
        for event in tail:
            self.ingest(event)

    def snapshot(self):
        return Snapshot.capture(self.window, self.checkpoint)
