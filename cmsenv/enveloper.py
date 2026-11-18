from .cmsstore import Store
from .content import content_key, wrap
from .envelopes import Envelope, EnvelopeState


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.recipient_keys = {1: {"alice": b"alice-cms-v1", "amy": b"amy-cms-v1"}}
        self.envelopes = {}

    def begin(self, identifier, content):
        envelope = Envelope(identifier, content, self.generation)
        self.envelopes[identifier] = envelope
        self.store.append("envelope_started", identifier=identifier, generation=self.generation)
        return content_key(identifier, content)

    def add_recipient(self, identifier, recipient):
        envelope = self.envelopes[identifier]
        envelope.state = EnvelopeState.SEALING
        envelope.recipients.append(recipient)
        if recipient not in self.recipient_keys[self.generation]:
            raise ValueError("unknown recipient")
        self.store.append("recipient_added", identifier=identifier, recipient=recipient)

    def rotate(self, keys):
        self.generation += 1
        self.recipient_keys[self.generation] = keys
        self.store.append("recipient_keys_rotated", generation=self.generation)

    def seal(self, identifier):
        envelope = self.envelopes[identifier]
        cek = content_key(identifier, envelope.content)
        for recipient in envelope.recipients:
            # Re-wrapping at seal time breaks recipients added before a rotation.
            envelope.wrapped[recipient] = wrap(cek, self.recipient_keys[self.generation][recipient], recipient, self.generation)
        envelope.state = EnvelopeState.SEALED
        self.store.append("envelope_sealed", identifier=identifier, generation=self.generation)
        return {"recipients": list(envelope.recipients), "wrapped": dict(envelope.wrapped)}

    def abort(self, identifier):
        self.envelopes[identifier].state = EnvelopeState.ABORTED

    def audit(self):
        return {"states": {k: v.state.value for k, v in self.envelopes.items()}}
