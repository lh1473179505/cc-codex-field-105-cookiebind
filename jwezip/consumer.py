"""JSON serialization recovery also accepts legacy uncompressed empty bodies."""
from .compression import decompress
from .model import TokenState, TokenTransaction


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "token_issued":
            service.transactions[event["identifier"]] = TokenTransaction(event["identifier"], event.get("generation", 1))
            service.buffers[event["identifier"]] = []
            restored.append(event["identifier"])
        elif event["kind"] == "token_sealed":
            service.transactions[event["identifier"]].state = TokenState.SEALED
    return {"restored": restored, "legacy_empty": decompress(b"", legacy=True).decode()}
