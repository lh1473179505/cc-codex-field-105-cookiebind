class Windows:
    def __init__(self):
        self.sent = {}

    def reserve(self, frame):
        self.sent[frame.stream] = self.sent.get(frame.stream, 0) + len(frame.payload)
