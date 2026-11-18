import json
from pathlib import Path

class Database:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "sysctl.json"
        self.data = {
            "runtime": {"kernel": {"kernel.randomize_va_space": 2},
                        "net.ipv4": {"net.ipv4.conf.all.rp_filter": 1}},
            "persistent": {"kernel": {"kernel.randomize_va_space": 2},
                           "net.ipv4": {"net.ipv4.conf.all.rp_filter": 1}},
            "intents": [], "epoch": 4, "active": {},
        }

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
