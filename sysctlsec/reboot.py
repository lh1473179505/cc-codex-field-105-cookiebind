from . import machine

def recover(db):
    recovered = []
    for item in db.data["intents"]:
        if item["status"] == machine.RUNTIME_WRITTEN:
            db.data["persistent"][item["namespace"]][item["key"]] = item["value"]
            item["status"] = machine.COMMITTED
            recovered.append(item["token"])
    db.save()
    return recovered
