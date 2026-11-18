from dataclasses import dataclass
from enum import Enum


class TokenState(Enum):
    REQUESTED = "requested"
    VERIFIED = "verified"
    ARCHIVED = "archived"
    REJECTED = "rejected"


@dataclass
class PendingToken:
    identifier: str
    imprint: str
    nonce: str
    tsa_generation: int
    state: TokenState = TokenState.REQUESTED
