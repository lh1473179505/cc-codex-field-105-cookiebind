import json
from pathlib import Path


class Snapshots:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "snapshot.json"
        if not self.path.exists():
            # Keep a complete initial role set for existing readers.
            self.write({"root": {"name": "root", "version": 1, "epoch": 1, "envelope": 1}})

    def write(self, roles):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"roles": roles}, sort_keys=True))
        temporary.replace(self.path)

    def all(self):
        return json.loads(self.path.read_text())["roles"]

    def legacy(self):
        return {
            "format": 1,
            "roles": {
                name: {"version": value["version"]}
                for name, value in self.all().items()
            },
        }
