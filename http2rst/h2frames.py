from dataclasses import dataclass

@dataclass(frozen=True)
class Frame:
    epoch: int
    stream: int
    kind: str
    payload: str
