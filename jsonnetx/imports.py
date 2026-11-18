import hashlib
import json
from pathlib import Path


class ImportClosure:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def freeze(self, imports):
        ordered = {name: imports[name] for name in sorted(imports)}
        raw = json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / digest[:2] / (digest + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return digest, ordered
