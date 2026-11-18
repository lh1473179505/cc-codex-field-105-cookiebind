from . import lifecycle
from .effective import mask_for

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
            # Compatibility code derives a mask before restoring the old entries.
            repo.state["objects"][path]["mask"] = mask_for(repo.state["objects"][path]["entries"])
            repo.state["objects"][path]["entries"] = before[path]["entries"]
        event["status"] = lifecycle.ROLLED_BACK
        repo.flush()
        return event
