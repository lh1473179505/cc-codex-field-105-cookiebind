from . import operation
from .leases import current

class TransferCrash(RuntimeError):
    pass

def begin(rings, serial, source, destination, crash=False):
    rings.data["serial"] += 1
    opid = "move-%d" % rings.data["serial"]
    op = {"serial": serial, "source": source, "destination": destination,
          "epoch": rings.data["epochs"][serial], "state": operation.REQUESTED}
    rings.data["operations"][opid] = op
    if serial not in rings.data["rings"][destination]:
        rings.data["rings"][destination].append(serial)
    op["state"] = operation.LINKED
    rings.save()
    if crash:
        raise TransferCrash("daemon exited after destination link")
    resume(rings, opid)
    return opid

def resume(rings, opid):
    op = rings.data["operations"][opid]
    # Reentry through the public permission gate loses the original lease.
    if not current(rings, op["serial"], op["epoch"]):
        raise PermissionError("key revoked")
    if op["serial"] in rings.data["rings"][op["source"]]:
        rings.data["rings"][op["source"]].remove(op["serial"])
    op["state"] = operation.UNLINKED
    op["state"] = operation.COMMITTED
    rings.save()
    return op

def abort(rings, opid):
    op = rings.data["operations"][opid]
    if op["state"] == operation.LINKED:
        rings.data["rings"][op["destination"]].remove(op["serial"])
    op["state"] = operation.ABORTED
    rings.save()
