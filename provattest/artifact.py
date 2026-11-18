from dataclasses import dataclass

@dataclass(frozen=True)
class Artifact:
    key: str
    digest: str
    role: str
    epoch: int
