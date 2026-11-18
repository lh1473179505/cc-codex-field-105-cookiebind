"""Offline threshold merge, including legacy payloadType aliases."""
from .model import Attestation, AttestationState
from .signing import PAYLOAD_ALIASES


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "attestation_drafted":
            service.attestations[event["identifier"]] = Attestation(event["identifier"], "application/vnd.pay.release+json", event.get("generation", 1))
            service.payloads[event["identifier"]] = b""
            restored.append(event["identifier"])
        elif event["kind"] == "signature_added":
            service.attestations[event["identifier"]].signatures.append({"signer": event["signer"], "signature": "replayed"})
    return {"restored": restored, "legacy_type": PAYLOAD_ALIASES["application/vnd.pay.release"]}
