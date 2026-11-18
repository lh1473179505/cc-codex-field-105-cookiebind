from .dssestore import Store
from .model import Attestation, AttestationState
from .signing import sign


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.signer_keys = {1: {"alice": b"alice-dsse-v1", "amy": b"amy-dsse-v1"}}
        self.attestations = {}
        self.payloads = {}

    def draft(self, identifier, payload, payload_type="application/vnd.pay.release+json"):
        self.attestations[identifier] = Attestation(identifier, payload_type, self.generation)
        self.payloads[identifier] = payload
        self.store.append("attestation_drafted", identifier=identifier, generation=self.generation)

    def rotate(self, keys):
        self.generation += 1
        self.signer_keys[self.generation] = keys
        self.store.append("signer_keys_rotated", generation=self.generation)

    def add_signature(self, identifier, signer, supplied=None):
        attestation = self.attestations[identifier]
        if any(entry["signer"] == signer for entry in attestation.signatures):
            raise ValueError("duplicate signer")
        attestation.state = AttestationState.COLLECTING
        attestation.signatures.append({"signer": signer, "signature": supplied or "pending"})
        keys = self.signer_keys[self.generation]
        if signer not in keys:
            raise ValueError("unknown signer")
        expected = sign(keys[signer], attestation.payload_type, self.payloads[identifier])
        if supplied is not None and supplied != expected:
            raise ValueError("signature mismatch")
        attestation.signatures[-1]["signature"] = expected
        self.store.append("signature_added", identifier=identifier, signer=signer, generation=self.generation)
        return expected

    def seal(self, identifier):
        attestation = self.attestations[identifier]
        if len(attestation.signatures) < 2:
            raise ValueError("threshold not reached")
        attestation.state = AttestationState.SEALED
        return attestation

    def audit(self):
        return {"counts": {k: len(v.signatures) for k, v in self.attestations.items()}}
