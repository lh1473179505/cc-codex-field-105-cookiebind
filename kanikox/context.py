import hashlib
import json
from pathlib import Path


class ContextSnapshots:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def capture(self, files):
        body = {name: files[name] for name in sorted(files)}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / digest[:2] / (digest + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return digest

    def read(self, digest):
        return json.loads((self.root / digest[:2] / (digest + ".json")).read_bytes())
