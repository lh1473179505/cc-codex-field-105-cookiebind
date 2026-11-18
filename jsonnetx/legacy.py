from pathlib import Path


class LegacyOutput:
    def __init__(self, root):
        self.root = Path(root)

    def read(self, path):
        destination = self.root / path
        if not destination.exists():
            raise RuntimeError("legacy output disappeared: " + path)
        return destination.read_text()

    def manifest(self):
        return sorted(str(path.relative_to(self.root)) for path in self.root.glob("legacy/*.json"))
