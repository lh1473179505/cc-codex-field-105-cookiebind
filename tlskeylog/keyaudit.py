"""Read-only diagnostic projection used by operators and existing consumers."""
from tlskeylog.ringlog import Store


def inspect(workspace):
    store = Store(workspace)
    return {
        "event_count": len(store.events()),
        "audit_count": len(store.audit_records()),
        "fingerprint": store.fingerprint(),
        "snapshot": store.snapshot(),
    }
