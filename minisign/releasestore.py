"""Durable JSON snapshot and append-only event storage."""
import hashlib
import json
import os
from pathlib import Path


class Store:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshot_path = self.root / "snapshot.json"
        self.event_path = self.root / "events.jsonl"
        self.audit_path = self.root / "audit.jsonl"

    def snapshot(self):
        if not self.snapshot_path.exists():
            return {}
        return json.loads(self.snapshot_path.read_text(encoding="utf-8"))

    def save_snapshot(self, value):
        self._atomic(self.snapshot_path, json.dumps(value, sort_keys=True, indent=2) + "\n")

    def append(self, kind, **payload):
        event = {"kind": kind, **payload}
        with self.event_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return event

    def events(self):
        if not self.event_path.exists():
            return []
        return [json.loads(line) for line in self.event_path.read_text(encoding="utf-8").splitlines() if line]

    def record_audit(self, action, **payload):
        with self.audit_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps({"action": action, **payload}, sort_keys=True) + "\n")

    def audit_records(self):
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]

    def fingerprint(self):
        digest = hashlib.sha256()
        for path in (self.snapshot_path, self.event_path, self.audit_path):
            digest.update(path.name.encode())
            digest.update(path.read_bytes() if path.exists() else b"")
        return digest.hexdigest()

    @staticmethod
    def _atomic(path, text):
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(text, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
