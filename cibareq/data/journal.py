"""Durable JSON state and append-only journal for CIBA 后端认证轮询接管."""
from __future__ import annotations

import json
from pathlib import Path


class JsonStore:
    def __init__(self, state_path: Path, journal_path: Path):
        self.state_path = Path(state_path)
        self.journal_path = Path(journal_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            self.data = json.loads(self.state_path.read_text(encoding="utf-8"))
        else:
            self.data = {"format": 1, "epochs": {}, "sessions": {}, "transactions": {}, "journal": [], "audit_views": 0}

    def epoch(self, authority: str) -> int:
        return self.data["epochs"].get(authority, 1)

    def save(self) -> None:
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(self.state_path)

    def append(self, operation: str, **fields) -> None:
        event = {"seq": len(self.data["journal"]) + 1, "op": operation, **fields}
        self.data["journal"].append(event)
        with self.journal_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
