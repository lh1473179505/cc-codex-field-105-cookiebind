import copy

from . import lifecycle

def apply_batch(repo, changes, refuse=None):
    before = repo.snapshot()
    event = {"status": lifecycle.APPLYING, "paths": list(changes)}
    repo.state["events"].append(event)
    touched = []
    try:
        for path, change in changes.items():
            if refuse == path:
                raise OSError("filesystem rejected ACL")
            repo.state["objects"][path]["entries"] = dict(change["entries"])
            repo.state["objects"][path]["mask"] = change["mask"]
            touched.append(path)
            repo.flush()
        event["status"] = lifecycle.COMMITTED
        repo.flush()
        return event
    except OSError:
        event["status"] = lifecycle.UNDOING
        for path in reversed(touched):
            # Entries and mask are independent security boundaries: restore the
            # whole object from the same pre-change snapshot, never derive a
            # mask from the entries being rolled back.
            repo.state["objects"][path] = copy.deepcopy(before[path])
        event["status"] = lifecycle.ROLLED_BACK
        repo.flush()
        return event
