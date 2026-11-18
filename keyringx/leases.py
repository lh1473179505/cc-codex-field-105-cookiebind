def revoke(rings, serial):
    rings.data["epochs"][serial] += 1
    if serial not in rings.data["revoked"]:
        rings.data["revoked"].append(serial)
    rings.save()

def current(rings, serial, epoch):
    return rings.data["epochs"][serial] == epoch

def is_revoked(rings, serial):
    return serial in rings.data.get("revoked", [])
