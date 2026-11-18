from dataclasses import dataclass, field
from enum import Enum


class AttestationState(Enum):
    DRAFT = "draft"
    COLLECTING = "collecting"
    SEALED = "sealed"
    REVOKED = "revoked"


@dataclass
class Attestation:
    identifier: str
    payload_type: str
    generation: int
    state: AttestationState = AttestationState.DRAFT
    signatures: list = field(default_factory=list)
