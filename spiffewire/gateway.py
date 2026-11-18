from .batch import BatchWindow
from .channel import Channel
from .identity import Bundle
from .journal import Journal

class Gateway:
    def __init__(self, fail=()):
        self.bundle = Bundle()
        self.window = BatchWindow()
        self.channel = Channel(fail)

    def begin(self, packets):
        return self.window.stage(packets, self.bundle)

    def commit(self, token):
        return self.window.flush(token, self.channel)

    def publish(self, packets):
        token = self.begin(packets)
        try:
            return self.commit(token)
        except RuntimeError:
            self.window.open.pop(token, None)
            raise

    def snapshot(self):
        return Journal().capture(self.window, self.bundle)

    def restore(self, state):
        self.window, self.bundle = Journal().restore(state)
