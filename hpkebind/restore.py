"""Offline ingest handles v0 records without a generation field."""
from .contexts import RecipientContext, SessionState


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "context_started":
            context = RecipientContext(event["session"], "pay-hpke-01", event.get("generation", 1))
            service.sessions[event["session"]] = context
            restored.append(event["session"])
        elif event["kind"] == "record_sealed":
            context = service.sessions[event["session"]]
            context.state = SessionState.SEALED
    return {"restored": restored, "format": "v0-compatible"}
