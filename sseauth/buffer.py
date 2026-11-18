class Buffer:
    def __init__(self):
        self.events = []

    def append(self, events):
        self.events.extend(events)

    def ordered_tail(self):
        return sorted(self.events, key=lambda e: e.sequence)
