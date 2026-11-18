from .archiver import Archive
from .fanout import Fanout
from .ledger import Ledger
from .subscriptions import Registry

class Worker:
    def __init__(self):
        self.registry = Registry()
        self.ledger = Ledger()

    def subscribe(self, subscriber):
        self.registry.add(subscriber)

    def publish(self, notices):
        return Fanout(self.registry, self.ledger).publish(notices)

    def snapshot(self):
        return Archive.save(self.ledger)

    def restore(self, state):
        self.ledger = Archive.open(state)
