class Writer:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.rows = []
        self.written = set()

    def flush(self, frames, table, windows):
        accepted = [f for f in frames if table.accepts(f)]
        for frame in accepted:
            self.written.add((frame.epoch, frame.stream, frame.kind, frame.payload))
            windows.reserve(frame)
            if frame.payload in self.fail:
                raise OSError(frame.payload)
            self.rows.append((frame.epoch, frame.stream, frame.payload))
