from dataclasses import dataclass

@dataclass(frozen=True)
class Finding:
    key: str
    rule: str
    severity: str
    epoch: int
    finger: str
