import json
from pathlib import Path


class Destinations:
    def __init__(self, root):
        self.path = Path(root) / "destinations.json"
        if not self.path.exists():
            self.save({})

    def save(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.path)

    def all(self):
        return json.loads(self.path.read_text())

    def put(self, tag, digest, sequence):
        value = self.all()
        value[tag] = {"digest": digest, "sequence": sequence}
        self.save(value)
