class Storage:
    def __init__(self):
        self.items = {}
        self.next_receipt = 0

    def enqueue(self, item):
        if item.key not in self.items:
            self.items[item.key] = item

    def available(self):
        return [i for i in self.items.values() if i.state == "available"]

    def export(self):
        return {"format": "queue-v1", "items": [
            {"key": i.key, "body": i.body, "state": i.state, "receipt": i.receipt}
            for i in self.items.values()]}

    def load(self, state):
        from .queue_model import Item
        self.items = {r["key"]: Item(**r) for r in state["items"]}
