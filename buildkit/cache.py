import json
from pathlib import Path


class CacheManifests:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def write(self, name, layers, epoch):
        record = {"name": name, "layers": layers, "epoch": epoch}
        (self.root / (name + ".json")).write_text(json.dumps(record, sort_keys=True))

    def read(self, name):
        return json.loads((self.root / (name + ".json")).read_text())

    def names(self):
        return sorted(path.stem for path in self.root.glob("*.json"))
