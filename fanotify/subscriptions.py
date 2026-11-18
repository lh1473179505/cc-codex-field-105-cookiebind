from . import phases

def revoke(broker, subscription):
    item = broker.data["subscriptions"][subscription]
    item["state"] = phases.REVOKED
    item["epoch"] += 1
    broker.save()

def drained(broker, subscription):
    waiting = [e for e in broker.data["events"].values()
               if e["subscription"] == subscription and e["state"] == phases.WAITING]
    return not waiting
