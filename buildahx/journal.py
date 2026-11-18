import json
from pathlib import Path


class BuildJournal:
    def __init__(self, root):
        self.path = Path(root) / "build-events.jsonl"
        self.path.touch()

    def append(self, tx, state, layer=None):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"tx": tx, "state": state, "layer": layer}, sort_keys=True) + "\n")

    def events(self):
        return [json.loads(line) for line in self.path.read_text().splitlines()]

    def committed_layers(self):
        # The original replayer treats per-layer commit as sufficient.
        return [event["layer"] for event in self.events() if event["state"] == "layer-committed"]
