import hashlib
import json
from pathlib import Path


class NarStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def add(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        name = digest + "-release"
        path = self.root / name[:2] / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return name, digest

    def path(self, name):
        return self.root / name[:2] / name

    def remove(self, name):
        path = self.path(name)
        if path.exists():
            path.unlink()
