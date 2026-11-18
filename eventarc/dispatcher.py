class Dispatcher:
    def __init__(self, sink):
        self.pending = {}
        self.handled = set()
        self.sink = sink

    def accept(self, record, watermarks):
        if record.event_id in self.handled or watermarks.stale(record):
            return []
        self.handled.add(record.event_id)
        watermarks.observe(record)
        self.pending[(record.channel, record.sequence)] = record
        if not record.closes:
            return []
        keys = sorted(k for k in self.pending if k[0] == record.channel)
        batch = [self.pending.pop(k) for k in keys]
        for item in batch:
            self.sink.emit(item)
        return batch
