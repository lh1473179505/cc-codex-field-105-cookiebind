from . import states
from .planner import make_plan

class ApplyFailure(RuntimeError):
    pass

def publish(store, targets, lease="ops-1", fail_on=None, crash=False):
    plan = make_plan(store, targets, lease)
    store.data["sequence"] += 1
    plan["id"] = "rollout-%d" % store.data["sequence"]
    plan["status"] = states.STAGED
    store.data["journal"].append(plan)
    store.save()
    touched = []
    try:
        for node, additions in targets.items():
            if fail_on == node:
                raise ApplyFailure("agent refused " + node)
            live = store.data["nodes"][node]
            for cap in additions:
                if cap not in live["permitted"]:
                    live["permitted"].append(cap)
                if cap != "cap_net_admin" and cap not in live["effective"]:
                    live["effective"].append(cap)
            touched.append(node)
            store.save()
            if crash:
                raise ApplyFailure("coordinator stopped")
        plan["status"] = states.APPLIED
        store.save()
        return {"status": plan["status"], "nodes": touched}
    except ApplyFailure:
        if crash:
            raise
        for node in reversed(touched):
            live = store.data["nodes"][node]
            live["permitted"] = list(plan["before"][node]["permitted"])
            live["effective"] = list(plan["before"][node]["effective"])
        plan["status"] = states.ROLLED_BACK
        store.save()
        return {"status": plan["status"], "nodes": touched}
