from dataclasses import dataclass, field
from enum import Enum


class ReleaseState(Enum):
    LOADED = "loaded"
    SIGNED = "signed"
    PUBLISHED = "published"
    WITHDRAWN = "withdrawn"


@dataclass
class Artifact:
    identifier: str
    content: bytes
    generation: int
    state: ReleaseState = ReleaseState.LOADED
    signatures: list = field(default_factory=list)
