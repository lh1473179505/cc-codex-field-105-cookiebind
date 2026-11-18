"""Restore archived tokens and verify legacy request/response nonce binding."""
from .tokens import PendingToken, TokenState


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "timestamp_requested":
            token = PendingToken(
                event["identifier"],
                event.get("imprint", ""),
                event["nonce"],
                event.get("generation", 1),
            )
            service.pending[token.identifier] = token
            restored.append(token.identifier)
        elif event["kind"] == "timestamp_verified":
            service.pending[event["identifier"]].state = TokenState.VERIFIED
        elif event["kind"] == "timestamp_archived":
            token = service.pending[event["identifier"]]
            token.state = TokenState.ARCHIVED
            if event.get("imprint"):
                token.imprint = event["imprint"]
            token.tsa_generation = event.get("generation", token.tsa_generation)
        elif event["kind"] == "tsa_rotated":
            service.generation = event["generation"]
            service.certificates.setdefault(event["generation"], "recovered-tsa-cert")
    return {"restored": restored, "legacy_policy_default": True}
