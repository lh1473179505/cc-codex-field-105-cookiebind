import json
from pathlib import Path


class KeyEpochs:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "epochs.json"
        if not self.path.exists():
            self.rotate(1, {"root": "root-one"}, set())

    def _read(self):
        return json.loads(self.path.read_text())

    def rotate(self, epoch, keys, revoked):
        state = self._read() if self.path.exists() else {"history": {}}
        state["current"] = epoch
        state["history"][str(epoch)] = {"keys": keys, "revoked": sorted(revoked)}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, sort_keys=True))
        temporary.replace(self.path)

    def current(self):
        state = self._read()
        return state["current"], state["history"][str(state["current"])]

    def at(self, epoch):
        return self._read()["history"][str(epoch)]
