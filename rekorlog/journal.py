import json
from pathlib import Path


class Journal:
    """Allocates public indexes while an append is still staged."""
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "state.json"
        self.events_path = self.root / "events.jsonl"
        if not self.state_path.exists():
            self._save({"next_index": 0})
        if not self.events_path.exists():
            self.events_path.write_text("")

    def _save(self, state):
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True))
        temporary.replace(self.state_path)

    @property
    def next_index(self):
        return json.loads(self.state_path.read_text())["next_index"]

    def event(self, kind, tx, entries):
        with self.events_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"kind": kind, "tx": tx, "entries": entries}, sort_keys=True) + "\n")
            stream.flush()

    def begin(self, tx, blobs):
        state = json.loads(self.state_path.read_text())
        entries = []
        for blob in blobs:
            entries.append({"index": state["next_index"], "blob": blob, "tx": tx})
            state["next_index"] += 1
        self._save(state)
        self.event("prepared", tx, entries)
        return entries

    def committed(self):
        result = []
        if not self.events_path.exists():
            return result
        for line in self.events_path.read_text().splitlines():
            event = json.loads(line)
            if event["kind"] == "committed":
                result.extend(event["entries"])
        return sorted(result, key=lambda item: item["index"])
