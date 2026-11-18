from .buffer import Buffer
from .resume import Resume
from .snapshot import Snapshot
from .tokens import Tokens

class Client:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.rows = []

    def write(self, event):
        if event.data in self.fail:
            raise OSError(event.data)
        self.rows.append((event.event_id, event.data))

class Feed:
    def __init__(self, client, tokens):
        self.client = client
        self.tokens = tokens
        self.buffer = Buffer()
        self.resume = Resume()

    def subscribe(self, token, events):
        if not self.tokens.valid(token):
            return []
        self.buffer.append(events)
        delivered = []
        for event in self.buffer.ordered_tail():
            if self.resume.eligible(event):
                self.client.write(event)
                self.resume.mark(event)
                delivered.append(event.event_id)
        return delivered

    def snapshot(self):
        return Snapshot().save(self.resume)

    def restore(self, state):
        self.resume = Snapshot().load(state)
