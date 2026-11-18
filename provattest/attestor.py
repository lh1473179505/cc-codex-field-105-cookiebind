class Attestor:
    def __init__(self):
        self.draft = {}
        self.granted = set()

    def draft_batch(self, artifacts, policy):
        token = object()
        ok = [a for a in artifacts if policy.allow(a) and a.key not in self.granted]
        self.draft[token] = ok
        # BUG: grant before sealed store write
        self.granted.update(a.key for a in ok)
        return token

    def seal(self, token, store):
        batch = self.draft.pop(token, [])
        for artifact in batch:
            store.put(artifact)
        return batch
