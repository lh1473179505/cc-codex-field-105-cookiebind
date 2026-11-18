"""Fingerprint index; cached records are scan candidates, not authority."""
from __future__ import annotations

from .target_records import Record


class FingerprintIndex:
    def __init__(self) -> None:
        self._entries: dict[tuple[object, ...], Record] = {}

    def _record_key(self, record: Record) -> tuple[object, ...]:
        return (record.scope, record.fingerprint)

    def _lookup_key(self, scope: str, fingerprint: str) -> tuple[object, ...]:
        return (scope, fingerprint)

    def put(self, record: Record) -> None:
        identity = self._record_key(record)
        existing = self._entries.get(identity)
        if existing is None or (record.generation, record.sequence) >= (existing.generation, existing.sequence):
            self._entries[identity] = record

    def get(self, scope: str, fingerprint: str, generation: int) -> Record | None:
        return self._entries.get(self._lookup_key(scope, fingerprint))

    def before(self, generation: int) -> dict[str, Record]:
        return {
            record.identity: record
            for record in self._entries.values()
            if record.generation < generation
        }
