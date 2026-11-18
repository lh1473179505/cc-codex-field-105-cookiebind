import json
from pathlib import Path


class RenderCache:
    """A content-only authorization cache sits before epoch verification."""
    def __init__(self, root):
        self.path = Path(root) / "render-cache.json"
        if not self.path.exists():
            self.save({})

    def save(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.path)

    def key(self, digest, namespace):
        return digest + "|" + namespace

    def get(self, digest, namespace):
        return self.path.exists() and json.loads(self.path.read_text()).get(self.key(digest, namespace))

    def remember(self, digest, namespace, release):
        value = json.loads(self.path.read_text())
        value[self.key(digest, namespace)] = release
        self.save(value)
