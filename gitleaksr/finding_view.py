"""Derived current-state view consumed by legacy and audit readers."""
from __future__ import annotations

from .secret_records import Record, State


class Projector:
    def __init__(self) -> None:
        self._cached: list[Record] | None = None

    def view(self, state: State) -> list[Record]:
        records = [
            state.records[identity]
            for identity in sorted(state.records)
            if identity not in state.revoked
        ]
        return records
