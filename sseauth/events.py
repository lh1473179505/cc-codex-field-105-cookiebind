from dataclasses import dataclass

@dataclass(frozen=True)
class Event:
    event_id: str
    sequence: int
    epoch: int
    data: str
