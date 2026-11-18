import hashlib
import json
from pathlib import Path


class BlobStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, descriptor):
        raw = json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        path = self.root / digest.split(":", 1)[1][:2] / digest.split(":", 1)[1]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        result = dict(descriptor)
        result["digest"] = digest
        result["size"] = len(raw)
        return result

    def get(self, digest):
        value = digest.split(":", 1)[1]
        return json.loads((self.root / value[:2] / value).read_bytes())
