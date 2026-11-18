class Sink:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.rows = []

    def emit(self, record):
        if record.payload in self.fail:
            raise RuntimeError(record.payload)
        self.rows.append((record.channel, record.sequence, record.payload))
