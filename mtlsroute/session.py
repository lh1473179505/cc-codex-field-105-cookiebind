class SessionLedger:
    def __init__(self):
        self.staged = {}
        self.accepted = set()

    def begin(self, frames, trust):
        token = object()
        # BUG: snapshot admit at begin, ignore later rotate before commit
        batch = [f for f in frames if trust.admit(f) and f.key not in self.accepted]
        self.staged[token] = batch
        # BUG: mark accepted before durable send
        self.accepted.update(f.key for f in batch)
        return token

    def commit(self, token, wire):
        batch = self.staged.pop(token, [])
        for frame in batch:
            wire.send(frame)
        return len(batch)

    def abort(self, token):
        batch = self.staged.pop(token, [])
        for frame in batch:
            self.accepted.discard(frame.key)
        return len(batch)
