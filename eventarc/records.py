from dataclasses import dataclass

@dataclass(frozen=True)
class Record:
    event_id: str
    channel: str
    sequence: int
    closes: bool
    payload: str
