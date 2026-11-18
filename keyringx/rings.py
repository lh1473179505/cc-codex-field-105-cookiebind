import json
from pathlib import Path

class Rings:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "rings.json"
        self.data = {"rings": {"pay-source": [101], "pay-dest": []},
                     "namespaces": {"pay-source": "pay", "pay-dest": "pay-dr"},
                     "epochs": {101: 3}, "operations": {}, "serial": 0}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
