"""Ordered operation journal shared by snapshot and incremental writers."""
from __future__ import annotations

from copy import deepcopy


class OperationJournal:
    def __init__(self) -> None:
        self._entries: list[dict[str, object]] = []

    def append(self, kind: str, sequence: int, generation: int, payload: dict[str, object]) -> dict[str, object]:
        if sequence <= 0 or generation <= 0:
            raise ValueError("sequence and generation must be positive")
        entry = {"kind": kind, "sequence": sequence, "generation": generation, "payload": deepcopy(payload)}
        self._entries.append(entry)
        return deepcopy(entry)

    def entries(self) -> list[dict[str, object]]:
        return deepcopy(self._entries)
