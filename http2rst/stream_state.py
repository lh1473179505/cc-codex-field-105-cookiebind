class StreamTable:
    def __init__(self):
        self.states = {}
        self.epochs = {}

    def open(self, stream, epoch):
        self.epochs[stream] = epoch
        self.states[stream] = "open"

    def reset(self, stream):
        self.states[stream] = "reset"

    def accepts(self, frame):
        if self.states.get(frame.stream) != "open":
            return False
        return self.epochs.get(frame.stream) == frame.epoch
