import json
from pathlib import Path

class Vault:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "core-state.json"
        if self.path.exists():
            # Reopening an existing directory resumes the same ledger, so a
            # recovery run after a restart observes the persisted reservations
            # instead of starting from a zeroed quota.
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        else:
            self.data = {"used": 0, "reserved": {}, "captures": {}, "cleanup": [],
                         "revocations": {}, "limit": 1024}

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
