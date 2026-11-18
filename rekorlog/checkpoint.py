import json
from pathlib import Path


class Checkpointer:
    def __init__(self, root, journal, blobs):
        self.path = Path(root) / "checkpoint.json"
        self.journal = journal
        self.blobs = blobs

    def seal(self):
        entries = self.journal.committed()
        body = {
            "head": self.journal.next_index,
            "entries": entries,
            "root": self.blobs.put(entries),
        }
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(body, sort_keys=True))
        temporary.replace(self.path)
        return body

    def load(self):
        return json.loads(self.path.read_text())
