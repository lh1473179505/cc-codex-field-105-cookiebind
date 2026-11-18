import hashlib
import json
from pathlib import Path


class ContentStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def add(self, target):
        raw = json.dumps(target, sort_keys=True).encode()
        key = hashlib.sha256(raw).hexdigest()
        path = self.root / key[:2] / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return key

    def read(self, key):
        return json.loads((self.root / key[:2] / key).read_bytes())
