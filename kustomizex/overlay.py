import hashlib
import json
from pathlib import Path


class OverlayStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, resources, namespace):
        value = {"resources": resources, "namespace": namespace}
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / digest[:2] / (digest + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return digest
