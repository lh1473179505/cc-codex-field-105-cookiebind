from dataclasses import dataclass

@dataclass(frozen=True)
class Fragment:
    session: str
    epoch: int
    message: str
    index: int
    final: bool
    text: str
