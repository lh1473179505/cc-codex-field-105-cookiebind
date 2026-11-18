from .bindings import Store
from .contexts import RecipientContext, SessionState
from .suites import seal


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.secrets = {1: b"recipient-private-key-v1"}
        self.sessions = {}

    def start(self, identifier, recipient="pay-hpke-01"):
        context = RecipientContext(identifier, recipient, self.generation)
        self.sessions[identifier] = context
        self.store.append("context_started", session=identifier, generation=context.generation)
        return context

    def rotate(self, secret):
        self.generation += 1
        self.secrets[self.generation] = secret
        self.store.append("recipient_rotated", generation=self.generation)

    def seal(self, identifier, plaintext, aad="pay:invoice:17", info="pay-hpke/v1"):
        context = self.sessions[identifier]
        record = seal(self.secrets[self.generation], self.generation, info, aad, plaintext)
        context.records.append(record)
        context.state = SessionState.SEALED
        self.store.append("record_sealed", session=identifier, generation=record["generation"], tag=record["tag"])
        if len(plaintext) > 64:
            raise ValueError("plaintext window exceeded")
        return record

    def export(self, identifier, legacy=False):
        context = self.sessions[identifier]
        context.state = SessionState.EXPORTED
        if legacy:
            return {"recipient": context.recipient, "records": [{k: v for k, v in r.items() if k != "generation"} for r in context.records]}
        return {"recipient": context.recipient, "generation": context.generation, "records": context.records}

    def audit(self):
        return {"generation": self.generation, "states": {k: v.state.value for k, v in self.sessions.items()}}
