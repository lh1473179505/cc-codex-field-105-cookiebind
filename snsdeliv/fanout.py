class Fanout:
    def __init__(self, registry, ledger):
        self.registry = registry
        self.ledger = ledger

    def publish(self, notices):
        batch = self.ledger.plan(notices)
        delivered = []
        for subscriber in self.registry.ordered():
            for notice in batch:
                subscriber.send(notice)
                delivered.append((subscriber.name, notice.key))
        return delivered
