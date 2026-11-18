"""Independent unseal/recovery path for current and pre-rotation envelopes."""
from .content import content_key, unwrap
from .envelopes import Envelope, EnvelopeState


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "envelope_started":
            service.envelopes[event["identifier"]] = Envelope(event["identifier"], b"", event.get("generation", 1))
            restored.append(event["identifier"])
        elif event["kind"] == "recipient_added":
            service.envelopes[event["identifier"]].recipients.append(event["recipient"])
    return {"restored": restored, "legacy_recipient_info": True}
