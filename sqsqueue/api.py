from .batch import BatchAck
from .remote import Remote
from .storage import Storage
from .visibility import Visibility

class Queue:
    def __init__(self, fail=()):
        self.storage = Storage()
        self.visibility = Visibility()
        self.remote = Remote(fail)

    def enqueue(self, item):
        self.storage.enqueue(item)

    def receive(self, limit=10):
        self.visibility.expire(self.storage.items.values())
        batch = self.storage.available()[:limit]
        for item in batch:
            self.visibility.hide(item)
        return [(i.key, i.receipt, i.body) for i in batch]

    def acknowledge(self, keys):
        BatchAck(self.storage, self.remote).delete(keys)

    def restore(self, state):
        self.storage.load(state)
