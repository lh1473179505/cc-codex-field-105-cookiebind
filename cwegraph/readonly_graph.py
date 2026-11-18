"""Version-one read-only output kept for existing report consumers."""
from __future__ import annotations

from .graph_records import State
from .graph_view import Projector


class LegacyReporter:
    def __init__(self, projector: Projector) -> None:
        self._projector = projector

    def render(self, state: State) -> dict[str, object]:
        records = self._projector.view(state)
        items = [record.public() for record in records]
        return {
            "schema": "scan-v1",
            "phase": state.phase,
            "generation": state.generation,
            "items": items,
            "revoked": sorted(state.revoked),
        }
