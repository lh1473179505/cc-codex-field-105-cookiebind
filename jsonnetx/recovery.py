import json
from pathlib import Path


class OutputRecovery:
    def __init__(self, root):
        self.root = Path(root)

    def clean_staged(self):
        journal = self.root / "output-journal.jsonl"
        states = []
        for line in journal.read_text().splitlines():
            states.append(json.loads(line))
        if states and states[-1]["state"] == "written":
            for event in states:
                if event["state"] == "written":
                    path = self.root / event["path"]
                    if path.exists():
                        path.unlink()
