def legacy_view(db):
    rows = []
    for namespace, values in db.data["runtime"].items():
        for key, value in values.items():
            durable = db.data["persistent"].get(namespace, {}).get(key)
            rows.append({"key": key, "namespace": namespace, "runtime": value,
                         "persistent": durable, "consistent": value == durable})
    return {"settings": rows, "pending": len([x for x in db.data["intents"]
                                               if x["status"] != "committed"])}
