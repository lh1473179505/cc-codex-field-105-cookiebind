class Writer:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.rows = []
        self.written = set()

    def flush(self, frames, table, windows):
        accepted = [f for f in frames if table.accepts(f)]
        for frame in accepted:
            key = (frame.epoch, frame.stream, frame.kind, frame.payload)
            if key in self.written:
                continue
            if frame.payload in self.fail:
                raise OSError(frame.payload)
            self.written.add(key)
            windows.reserve(frame)
            self.rows.append((frame.epoch, frame.stream, frame.payload))
