"""Crash recovery replays epoch boundaries before resuming old derivations."""
from .kdf import derive


def recover(service, events):
    resumed = []
    for event in events:
        if event["kind"] == "epoch_activated" and event["epoch"] not in service.epochs:
            raise ValueError("recovery needs the registered secret")
        if event["kind"] == "derivation_started":
            service.begin(event["identifier"])
            resumed.append(event["identifier"])
    return {"resumed": resumed, "legacy_v0_digest": derive(service.epochs[1].secret, "pay/api/v1", legacy=True).hex()}
