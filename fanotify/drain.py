from . import phases

def recover(broker):
    expired = []
    for event_id, event in broker.data["events"].items():
        if event["state"] == phases.WAITING:
            event["state"] = phases.CLOSED
            broker.data["decisions"].append({"event": event_id, "decision": "deny",
                                             "epoch": event["epoch"]})
            expired.append(event_id)
    broker.save()
    return expired
