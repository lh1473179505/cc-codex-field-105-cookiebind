"""Streaming replay for chunk-oriented producers and v1 algorithm aliases."""
from .model import DocumentState, DocumentTransaction


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "document_loaded":
            service.transactions[event["identifier"]] = DocumentTransaction(event["identifier"], event.get("generation", 1), DocumentState.KEYED)
            restored.append(event["identifier"])
        elif event["kind"] == "fragment_sealed":
            tx = service.transactions[event["identifier"]]
            tx.fragments[event["reference"]] = ""
            tx.state = DocumentState.SEALED
    return {"restored": restored, "legacy_alias": "rsa-oaep-mgf1p"}
