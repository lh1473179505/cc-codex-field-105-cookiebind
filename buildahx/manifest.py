import json
from pathlib import Path


class Manifest:
    def __init__(self, root):
        self.path = Path(root) / "manifest.json"
        if not self.path.exists():
            self.write({"schema": 2, "layers": [], "epoch": 1})

    def read(self):
        return json.loads(self.path.read_text())

    def write(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.path)

    def replace_layers(self, layers):
        value = self.read()
        value["layers"] = list(layers)
        self.write(value)
