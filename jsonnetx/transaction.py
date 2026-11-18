import json
from pathlib import Path


class OutputTransaction:
    """Rollback tracks new paths but not overwritten file contents."""
    def __init__(self, root):
        self.root = Path(root)
        self.journal = self.root / "output-journal.jsonl"
        self.journal.touch()
        self.written = []

    def stage(self, path, content):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content)
        self.written.append(destination)
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"state": "written", "path": path}) + "\n")

    def rollback(self):
        for path in reversed(self.written):
            if path.exists():
                path.unlink()
        self.written.clear()
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"state": "aborted"}) + "\n")

    def commit(self):
        self.written.clear()
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"state": "committed"}) + "\n")
