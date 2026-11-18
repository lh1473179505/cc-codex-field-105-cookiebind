import json
from pathlib import Path

class Vault:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "core-state.json"
        self.data = {"used": 0, "reserved": {}, "captures": {}, "cleanup": [],
                     "revocations": {}, "limit": 1024}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
