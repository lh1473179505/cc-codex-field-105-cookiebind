import hashlib
from pathlib import Path


class ContentStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data):
        raw = data.encode()
        key = hashlib.sha256(raw).hexdigest()
        path = self.root / key[:2] / (key + ".layer")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return key

    def path(self, key):
        return self.root / key[:2] / (key + ".layer")

    def read(self, key):
        return self.path(key).read_text()

    def remove(self, key):
        path = self.path(key)
        if path.exists():
            path.unlink()
