class Resume:
    def __init__(self):
        self.last_sequence = 0
        self.sent = set()

    def eligible(self, event):
        return event.sequence > self.last_sequence and event.event_id not in self.sent

    def mark(self, event):
        self.last_sequence = max(self.last_sequence, event.sequence)
        self.sent.add(event.event_id)

    def capture(self):
        return {"last_sequence": self.last_sequence, "sent": sorted(self.sent)}
