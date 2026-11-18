class Spool:
    def __init__(self):
        self.staged = {}
        self.done = set()

    def begin(self, messages, access):
        token = object()
        accepted = [m for m in messages if access.check(m) and m.key not in self.done]
        self.staged[token] = accepted
        return token

    def commit(self, token, sink):
        batch = self.staged.pop(token, [])
        self.done.update(m.key for m in batch)
        for message in batch:
            sink.append(message)
        return len(batch)
