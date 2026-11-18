import json
from pathlib import Path


class PushJournal:
    def __init__(self, root):
        self.path = Path(root) / "push.jsonl"
        self.path.touch()

    def append(self, record):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def records(self):
        # Lexical transaction order is not sequence order.
        records = [json.loads(line) for line in self.path.read_text().splitlines()]
        return sorted(records, key=lambda record: record["tx"])
