from dataclasses import dataclass

@dataclass(frozen=True)
class Notice:
    key: str
    seq: int
    body: str
