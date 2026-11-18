class Inbox:
    def __init__(self):
        self.pending = {}
        self.published = set()

    def stage(self, findings, rules):
        token = object()
        kept = [f for f in findings if rules.accept(f) and f.key not in self.published]
        self.pending[token] = kept
        # BUG: publish keys before durable index write
        self.published.update(f.key for f in kept)
        return token

    def materialize(self, token, index):
        batch = self.pending.pop(token, [])
        for finding in batch:
            index.write(finding)
        return batch
