"""Derived current-state view consumed by legacy and audit readers."""
from __future__ import annotations

from .graph_records import Record, State


class Projector:
    def __init__(self) -> None:
        self._cached: list[Record] | None = None

    def view(self, state: State) -> list[Record]:
        if self._cached is not None:
            return self._cached
        records = [
            state.records[identity]
            for identity in sorted(state.records)
            if identity not in state.revoked
        ]
        self._cached = records
        return records
