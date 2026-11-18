from dataclasses import dataclass, field
from enum import Enum


class SessionState(Enum):
    OPEN = "open"
    SEALED = "sealed"
    EXPORTED = "exported"
    REVOKED = "revoked"


@dataclass
class RecipientContext:
    session: str
    recipient: str
    generation: int
    state: SessionState = SessionState.OPEN
    records: list = field(default_factory=list)
