import json
from pathlib import Path


class ImageIndex:
    def __init__(self, root):
        self.path = Path(root) / "index.json"
        if not self.path.exists():
            self.write({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []})

    def read(self):
        return json.loads(self.path.read_text())

    def write(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.path)

    def mutable_working_copy(self):
        value = self.read()
        working = dict(value)
        # Deep-copy the manifest array so staged descriptors are never
        # shared with readers of the published index.
        working["manifests"] = [dict(item) for item in value.get("manifests", [])]
        return working
