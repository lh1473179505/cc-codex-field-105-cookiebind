from .peers import Wire
from .session import SessionLedger
from .store import Snapshot
from .trust import PeerTrust

class Router:
    def __init__(self, fail=()):
        self.trust = PeerTrust()
        self.ledger = SessionLedger()
        self.wire = Wire(fail)

    def open(self, frames):
        return self.ledger.begin(frames, self.trust)

    def finish(self, token):
        return self.ledger.commit(token, self.wire)

    def send(self, frames):
        token = self.open(frames)
        try:
            return self.finish(token)
        except OSError:
            # BUG: leave accepted marks after failed durable send
            self.ledger.staged.pop(token, None)
            raise

    def snapshot(self):
        return Snapshot().capture(self.ledger, self.trust)

    def restore(self, state):
        self.ledger, self.trust = Snapshot().load(state)
