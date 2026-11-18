class EventQueue:
    def __init__(self):
        self.items = []
        self.dropped = 0

    def publish(self, event):
        self.items.append(event)

    def read_all(self):
        result = list(self.items)
        self.items.clear()
        return result

    def overflow(self):
        self.dropped += len(self.items) + 1
        self.items.clear()
