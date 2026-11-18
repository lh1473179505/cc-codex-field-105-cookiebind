from .dispatcher import Dispatcher
from .sinks import Sink
from .snapshots import Snapshot
from .watermark import Watermarks

class Triggers:
    def __init__(self, fail=()):
        self.watermarks = Watermarks()
        self.sink = Sink(fail)
        self.dispatcher = Dispatcher(self.sink)

    def ingest(self, record):
        return self.dispatcher.accept(record, self.watermarks)

    def recover(self, state, records):
        Snapshot().restore(state, self.dispatcher, self.watermarks)
        for record in records:
            self.ingest(record)

    def snapshot(self):
        return Snapshot().save(self.dispatcher, self.watermarks)
