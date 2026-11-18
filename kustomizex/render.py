import json
from pathlib import Path


class Renderer:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def render(self, resources, namespace):
        documents = []
        for resource in resources:
            item = dict(resource)
            item.setdefault("metadata", {})
            item["metadata"]["namespace"] = namespace
            documents.append(item)
        raw = json.dumps(documents, sort_keys=True).encode()
        import hashlib
        digest = hashlib.sha256(raw).hexdigest()
        path = self.root / digest[:2] / (digest + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return digest, documents
