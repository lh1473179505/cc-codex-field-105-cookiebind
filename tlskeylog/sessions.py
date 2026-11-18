from .model import SessionState, TlsSession
from .ringlog import Store
from .secrets import traffic_secret


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.masters = {1: b"tls-master-key-v1"}
        self.sessions = {}

    def open(self, identifier):
        self.sessions[identifier] = TlsSession(identifier, self.generation)
        self.store.append("tls_session_opened", identifier=identifier, generation=self.generation)

    def rotate(self, master):
        self.generation += 1
        self.masters[self.generation] = master
        self.store.append("tls_master_rotated", generation=self.generation)

    def finish_handshake(self, identifier, client_random, label="CLIENT_HANDSHAKE_TRAFFIC_SECRET"):
        session = self.sessions[identifier]
        secret = traffic_secret(self.masters[self.generation], self.generation, client_random, label)
        session.secrets[label] = secret
        session.state = SessionState.READY
        self.store.append("tls_secret_recorded", identifier=identifier, generation=self.generation, label=label)
        return secret

    def close(self, identifier):
        self.sessions[identifier].state = SessionState.CLOSED

    def audit(self):
        # Existing diagnostics unexpectedly purge closed sessions and append an audit record.
        for session in self.sessions.values():
            if session.state == SessionState.CLOSED:
                session.state = SessionState.PURGED
                session.secrets.clear()
        self.store.record_audit("keylog_inspected", generation=self.generation)
        return {"states": {k: v.state.value for k, v in self.sessions.items()}}
