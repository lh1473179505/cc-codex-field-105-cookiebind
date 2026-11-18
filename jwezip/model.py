from dataclasses import dataclass
from enum import Enum


class TokenState(Enum):
    ISSUED = "issued"
    BUFFERED = "buffered"
    SEALED = "sealed"
    ABORTED = "aborted"


@dataclass
class TokenTransaction:
    identifier: str
    generation: int
    state: TokenState = TokenState.ISSUED
