import copy
import json
from pathlib import Path

class Repository:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "acl.json"
        self.state = {
            "objects": {
                "/srv/a": {"entries": {"user:alice": "r-x"}, "mask": "r--", "namespace": "pay"},
                "/srv/b": {"entries": {"group:ops": "r--"}, "mask": "r--", "namespace": "ops"},
            },
            "events": [], "aliases": {}, "generation": 1,
        }

    def snapshot(self):
        return copy.deepcopy(self.state["objects"])

    def flush(self):
        temp = self.path.with_suffix(".new")
        temp.write_text(json.dumps(self.state, sort_keys=True), encoding="utf-8")
        temp.replace(self.path)
