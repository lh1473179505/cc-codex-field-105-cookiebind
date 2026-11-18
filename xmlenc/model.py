from dataclasses import dataclass, field
from enum import Enum


class DocumentState(Enum):
    PARSED = "parsed"
    KEYED = "keyed"
    SEALED = "sealed"
    COMMITTED = "committed"


@dataclass
class DocumentTransaction:
    identifier: str
    generation: int
    state: DocumentState = DocumentState.PARSED
    fragments: dict = field(default_factory=dict)
