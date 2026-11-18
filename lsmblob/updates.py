from . import lifecycle

class HookFailure(RuntimeError):
    pass

def update_many(store, changes, fail=None):
    snapshots = store.snapshot(changes)
    record = {"names": list(changes), "phase": lifecycle.UPDATING}
    store.journal.append(record)
    touched = []
    try:
        for name, value in changes.items():
            if fail == name:
                raise HookFailure("secondary hook rejected update")
            store.items[name][:] = value
            touched.append(name)
        record["phase"] = lifecycle.ATTACHED
        return record
    except HookFailure:
        for name in reversed(touched):
            store.items[name][:] = snapshots[name]
        record["phase"] = "rolled_back"
        return record
