from dataclasses import dataclass
from enum import Enum


class EpochState(Enum):
    DRAFT = "draft"
    STAGED = "staged"
    ACTIVE = "active"
    RETIRED = "retired"


@dataclass
class Epoch:
    number: int
    secret: bytes
    state: EpochState


@dataclass
class DerivationTransaction:
    identifier: str
    epoch: int
    state: str = "open"
