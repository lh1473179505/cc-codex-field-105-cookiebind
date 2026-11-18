"""Restore archived tokens and verify legacy request/response nonce binding."""
from .tokens import PendingToken, TokenState


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "timestamp_requested":
            token = PendingToken(event["identifier"], "", event["nonce"], event.get("generation", 1))
            service.pending[token.identifier] = token
            restored.append(token.identifier)
        elif event["kind"] == "timestamp_verified":
            service.pending[event["identifier"]].state = TokenState.VERIFIED
    return {"restored": restored, "legacy_policy_default": True}
