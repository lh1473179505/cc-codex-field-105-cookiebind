from . import phases

def open_permission(broker, subscription, path):
    sub = broker.data["subscriptions"][subscription]
    if sub["state"] != phases.ACTIVE:
        raise PermissionError("subscription closed")
    broker.data["serial"] += 1
    event_id = "event-%d" % broker.data["serial"]
    broker.data["events"][event_id] = {"subscription": subscription, "path": path,
                                       "state": phases.WAITING, "epoch": sub["epoch"]}
    broker.save()
    return event_id

def respond(broker, event_id, allow):
    event = broker.data["events"][event_id]
    sub = broker.data["subscriptions"][event["subscription"]]
    # Current subscription state is incorrectly reused for an old operation.
    if sub["state"] != phases.ACTIVE:
        raise PermissionError("subscription revoked")
    decision = "allow" if allow else "deny"
    event["state"] = phases.ANSWERED
    broker.data["decisions"].append({"event": event_id, "decision": decision,
                                     "epoch": event["epoch"]})
    broker.save()
    return decision
