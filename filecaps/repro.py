import json
import tempfile
from .store import Store
from .coordinator import publish
from .legacy import audit_snapshot

def main():
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(tmp)
        store.data["leases"]["ops-1"] = {"epoch": 1}
        result = publish(store, {"alpha": ["cap_net_admin"], "beta": ["cap_net_raw"]},
                         fail_on="beta")
        snapshot = audit_snapshot(store)
        leaked = "cap_net_admin" in snapshot["nodes"]["alpha"]["permitted"]
        print(json.dumps({"result": result, "alpha_after_rollback": snapshot["nodes"]["alpha"],
                          "rollback_left_capability": leaked}, sort_keys=True))
        return 0 if result["status"] == "rolled_back" and leaked else 1
