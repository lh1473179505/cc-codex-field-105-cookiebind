import json
from pathlib import Path


class Transactions:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, tx, epoch, role):
        path = self.root / (tx + ".json")
        path.write_text(json.dumps({
            "tx": tx,
            "state": "prepared",
            "epoch": epoch,
            "role": role.record(),
        }, sort_keys=True))

    def load(self, tx):
        return json.loads((self.root / (tx + ".json")).read_text())

    def mark(self, tx, state):
        record = self.load(tx)
        record["state"] = state
        (self.root / (tx + ".json")).write_text(json.dumps(record, sort_keys=True))
