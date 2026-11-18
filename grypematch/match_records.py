"""In-memory records and the public state snapshot used by both paths."""
from __future__ import annotations

from dataclasses import dataclass, field
import json


@dataclass
class Record:
    key: str
    scope: str
    fingerprint: str
    value: str
    generation: int
    sequence: int

    @property
    def identity(self) -> str:
        return self.scope + ":" + self.key

    def public(self) -> dict[str, object]:
        return {
            "id": self.key,
            "scope": self.scope,
            "fingerprint": self.fingerprint,
            "value": self.value,
            "generation": self.generation,
            "sequence": self.sequence,
        }


@dataclass
class State:
    phase: str = "WAITING"
    generation: int = 0
    high_water: int = 0
    records: dict[str, Record] = field(default_factory=dict)
    revoked: dict[str, int] = field(default_factory=dict)
    history: list[str] = field(default_factory=list)

    def token(self) -> str:
        """Stable diagnostic token; producing it must not mutate state."""
        payload = {
            "phase": self.phase,
            "generation": self.generation,
            "high_water": self.high_water,
            "records": [self.records[key].public() for key in sorted(self.records)],
            "revoked": sorted(self.revoked.items()),
            "history": list(self.history),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
