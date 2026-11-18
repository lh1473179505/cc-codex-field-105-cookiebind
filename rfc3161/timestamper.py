import hashlib

from .imprints import request_frame, verify_frame
from .requests import Store
from .tokens import PendingToken, TokenState


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.certificates = {1: "tsa-pay-cert-v1"}
        self.pending = {}
        self.consumed_nonces = set()

    def request(self, identifier, payload, nonce):
        if nonce in self.consumed_nonces:
            raise ValueError("request nonce already consumed")
        if nonce in {item.nonce for item in self.pending.values()}:
            raise ValueError("request nonce already in flight")
        imprint = hashlib.sha256(payload).hexdigest()
        token = PendingToken(identifier, imprint, nonce, self.generation)
        self.pending[identifier] = token
        self.store.append(
            "timestamp_requested",
            identifier=identifier,
            imprint=imprint,
            nonce=nonce,
            generation=self.generation,
        )
        return request_frame(identifier, imprint, nonce, legacy=self.generation == 1)

    def rotate_tsa(self, certificate):
        self.generation += 1
        self.certificates[self.generation] = certificate
        self.store.append("tsa_rotated", generation=self.generation)

    def accept(self, identifier, frame):
        token = self.pending[identifier]
        value = verify_frame(frame, token.nonce)
        # The nonce is consumed only once the response frame has been verified.
        self.consumed_nonces.add(token.nonce)
        token.state = TokenState.VERIFIED
        self.store.append("timestamp_verified", identifier=identifier, generation=token.tsa_generation)
        return value

    def archive(self, identifier):
        token = self.pending[identifier]
        token.state = TokenState.ARCHIVED
        self.store.append(
            "timestamp_archived",
            identifier=identifier,
            imprint=token.imprint,
            nonce=token.nonce,
            generation=token.tsa_generation,
        )
        return {"id": identifier, "imprint": token.imprint, "generation": token.tsa_generation}

    def audit(self):
        return {"pending": sorted(self.pending), "consumed": len(self.consumed_nonces)}
