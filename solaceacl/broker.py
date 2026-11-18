from .acl import Access
from .domain import DurableSink
from .spool import Spool
from .store import StateStore

class Broker:
    def __init__(self, fail=()):
        self.access = Access()
        self.spool = Spool()
        self.sink = DurableSink(fail)

    def publish(self, messages):
        token = self.spool.begin(messages, self.access)
        return self.spool.commit(token, self.sink)

    def begin(self, messages):
        return self.spool.begin(messages, self.access)

    def commit(self, token):
        return self.spool.commit(token, self.sink)

    def restore(self, state):
        self.spool, self.access = StateStore().load(state)

    def snapshot(self):
        return StateStore().capture(self.spool, self.access)
