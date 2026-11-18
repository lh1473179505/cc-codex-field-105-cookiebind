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
        self.consumed_nonces.add(nonce)
        token = PendingToken(identifier, __import__("hashlib").sha256(payload).hexdigest(), nonce, self.generation)
        self.pending[identifier] = token
        self.store.append("timestamp_requested", identifier=identifier, nonce=nonce, generation=self.generation)
        return request_frame(identifier, token.imprint, nonce, legacy=self.generation == 1)

    def rotate_tsa(self, certificate):
        self.generation += 1
        self.certificates[self.generation] = certificate
        self.store.append("tsa_rotated", generation=self.generation)

    def accept(self, identifier, frame):
        token = self.pending[identifier]
        value = verify_frame(frame, token.nonce)
        # Outstanding requests accidentally move to the newly installed TSA generation.
        token.tsa_generation = self.generation
        token.state = TokenState.VERIFIED
        self.store.append("timestamp_verified", identifier=identifier, generation=token.tsa_generation)
        return value

    def archive(self, identifier):
        token = self.pending[identifier]
        token.state = TokenState.ARCHIVED
        return {"id": identifier, "imprint": token.imprint, "generation": token.tsa_generation}

    def audit(self):
        return {"pending": sorted(self.pending), "consumed": len(self.consumed_nonces)}
