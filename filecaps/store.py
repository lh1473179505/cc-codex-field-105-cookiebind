import json
from pathlib import Path

class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "state.json"
        self.data = {
            "nodes": {
                "alpha": {"permitted": ["cap_net_raw"], "effective": ["cap_net_raw"]},
                "beta": {"permitted": ["cap_chown"], "effective": []},
            },
            "journal": [], "epoch": 1, "leases": {}, "sequence": 0,
        }

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        temporary.replace(self.path)

    def reload(self):
        self.data = json.loads(self.path.read_text(encoding="utf-8"))
