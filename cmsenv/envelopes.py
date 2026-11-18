from dataclasses import dataclass, field
from enum import Enum


class EnvelopeState(Enum):
    COLLECTING = "collecting"
    SEALING = "sealing"
    SEALED = "sealed"
    ABORTED = "aborted"


@dataclass
class Envelope:
    identifier: str
    content: bytes
    generation: int
    state: EnvelopeState = EnvelopeState.COLLECTING
    recipients: list = field(default_factory=list)
    wrapped: dict = field(default_factory=dict)
