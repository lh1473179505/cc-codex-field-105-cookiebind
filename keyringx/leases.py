def revoke(rings, serial):
    rings.data["epochs"][serial] += 1
    rings.save()

def current(rings, serial, epoch):
    return rings.data["epochs"][serial] == epoch
