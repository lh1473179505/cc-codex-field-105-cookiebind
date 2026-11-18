from dataclasses import dataclass, field
from enum import Enum


class SessionState(Enum):
    HANDSHAKE = "handshake"
    READY = "ready"
    CLOSED = "closed"
    PURGED = "purged"


@dataclass
class TlsSession:
    identifier: str
    generation: int
    state: SessionState = SessionState.HANDSHAKE
    secrets: dict = field(default_factory=dict)
