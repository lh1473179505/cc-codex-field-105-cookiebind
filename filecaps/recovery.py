from . import states
from .coordinator import publish

def recover(store):
    pending = [p for p in store.data["journal"] if p["status"] == states.STAGED]
    results = []
    for plan in pending:
        lease = plan["lease"]
        if store.data["epoch"] != plan["epoch"]:
            plan["status"] = states.CANCELLED
            results.append(plan["id"])
            continue
        results.append(publish(store, plan["targets"], lease)["status"])
    store.save()
    return results
