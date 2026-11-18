"""Offline threshold merge, including legacy payloadType aliases."""
from .model import Attestation, AttestationState
from .signing import PAYLOAD_ALIASES
from .threshold import canonical_payload_type


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "attestation_drafted":
            payload_type = canonical_payload_type(event.get("payload_type", "application/vnd.pay.release+json"))
            service.attestations[event["identifier"]] = Attestation(event["identifier"], payload_type, event.get("generation", 1))
            service.payloads[event["identifier"]] = b""
            restored.append(event["identifier"])
        elif event["kind"] == "signature_added":
            attestation = service.attestations[event["identifier"]]
            if any(entry["signer"] == event["signer"] for entry in attestation.signatures):
                continue
            attestation.state = AttestationState.COLLECTING
            attestation.signatures.append({"signer": event["signer"], "signature": "replayed"})
    return {"restored": restored, "legacy_type": PAYLOAD_ALIASES["application/vnd.pay.release"]}
