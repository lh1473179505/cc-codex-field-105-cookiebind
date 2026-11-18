def key_audit(rings):
    locations = {}
    for ring, serials in rings.data["rings"].items():
        for serial in serials:
            locations.setdefault(str(serial), []).append(ring)
    return {"locations": locations,
            "operations": [{"id": opid, "state": op["state"], "epoch": op["epoch"]}
                           for opid, op in rings.data["operations"].items()]}
