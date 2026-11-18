from dataclasses import dataclass
from enum import Enum


class TokenState(Enum):
    CLOSED = "closed"
    LOGGED_IN = "logged-in"
    OPERATION_OPEN = "operation-open"
    COMMITTED = "committed"
    ABORTED = "aborted"


@dataclass
class Operation:
    identifier: str
    slot: int
    key_label: str
    generation: int
    state: TokenState = TokenState.OPERATION_OPEN
