from . import machine

def legacy_view(db):
    rows = []
    for namespace, values in db.data["runtime"].items():
        for key, value in values.items():
            durable = db.data["persistent"].get(namespace, {}).get(key)
            rows.append({"key": key, "namespace": namespace, "runtime": value,
                         "persistent": durable, "consistent": value == durable})
    return {"settings": rows, "pending": sum(
        1 for item in db.data["intents"] if item["status"] in machine.OPEN_STATES)}
