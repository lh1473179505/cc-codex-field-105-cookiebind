from . import states

def make_plan(store, targets, lease):
    if lease not in store.data["leases"]:
        raise PermissionError("unknown lease")
    before = {}
    for node in targets:
        # Historical optimization: the plan and live registry share capability lists.
        before[node] = store.data["nodes"][node]
    return {"lease": lease, "epoch": store.data["epoch"], "targets": targets,
            "before": before, "status": states.DRAFT}
