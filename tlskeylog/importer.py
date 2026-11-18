"""Replay chain imports TLS 1.2 CLIENT_RANDOM lines without live-handshake hooks."""
from .model import SessionState, TlsSession


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "tls_session_opened":
            service.sessions[event["identifier"]] = TlsSession(event["identifier"], event.get("generation", 1))
            restored.append(event["identifier"])
        elif event["kind"] == "tls_secret_recorded":
            service.sessions[event["identifier"]].state = SessionState.READY
    return {"restored": restored, "tls12_client_random": True}
