class Watermarks:
    def __init__(self):
        self.positions = {}

    def observe(self, record):
        old = self.positions.get(record.channel, 0)
        self.positions[record.channel] = max(old, record.sequence)

    def stale(self, record):
        return record.sequence < self.positions.get(record.channel, 0)
