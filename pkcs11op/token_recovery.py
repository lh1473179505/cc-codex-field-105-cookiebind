"""Token recovery path accepts legacy labels and never performs a fresh login."""
from .mechanisms import legacy_label
from .model import Operation


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "token_logged_in":
            service.handles.add(event["slot"])
        elif event["kind"] == "operation_started":
            label = legacy_label(event.get("key_label", "pay-sign"))
            service.operations[event["identifier"]] = Operation(event["identifier"], 7, label, event.get("generation", 1))
            restored.append(event["identifier"])
    return {"restored": restored, "legacy_label": legacy_label("pay-sign")}
