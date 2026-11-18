import json
from .blobs import BlobStore
from .hooks import Hooks
from .updates import update_many
from .legacy_audit import audit_blob

def main():
    store = BlobStore()
    hooks = Hooks(store)
    hooks.begin("open-1", "pay")
    result = update_many(store, {"pay": b"deny!;", "ops": b"write;"}, fail="ops")
    view = audit_blob(store, hooks, "open-1")
    changed = view["decision"] != "allow;"
    print(json.dumps({"result": result, "inflight_audit": view,
                      "rollback_corrupted_borrowed_view": changed}, sort_keys=True))
    return 0 if result["phase"] == "rolled_back" and changed else 1
