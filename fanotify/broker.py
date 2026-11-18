import json
from pathlib import Path

class Broker:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "broker.json"
        self.data = {"subscriptions": {"scan": {"state": "active", "epoch": 1}},
                     "events": {}, "decisions": [], "serial": 0}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
