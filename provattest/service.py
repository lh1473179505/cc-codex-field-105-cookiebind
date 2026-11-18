from .attestor import Attestor
from .policy import TrustPolicy
from .store import Checkpoint, SealStore

class Service:
    def __init__(self, fail=()):
        self.policy = TrustPolicy()
        self.attestor = Attestor()
        self.store = SealStore(fail)

    def begin(self, artifacts):
        return self.attestor.draft_batch(artifacts, self.policy)

    def commit(self, token):
        return self.attestor.seal(token, self.store)

    def attest(self, artifacts):
        token = self.begin(artifacts)
        try:
            return self.commit(token)
        except RuntimeError:
            self.attestor.draft.pop(token, None)
            raise

    def snapshot(self):
        return Checkpoint().capture(self.attestor, self.policy)

    def restore(self, state):
        self.attestor, self.policy = Checkpoint().load(state)
