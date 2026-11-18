from . import machine

def record(db, namespace, key, value, token):
    item = {"namespace": namespace, "key": key, "value": value, "token": token,
            "epoch": db.data["epoch"], "status": machine.PROPOSED,
            "before_runtime": db.data["runtime"][namespace][key],
            "before_persistent": db.data["persistent"][namespace][key]}
    db.data["intents"].append(item)
    db.save()
    return item
