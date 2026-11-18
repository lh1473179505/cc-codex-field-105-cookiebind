from . import operation
from .leases import current, is_revoked

class TransferCrash(RuntimeError):
    pass

def begin(rings, serial, source, destination, crash=False):
    if is_revoked(rings, serial):
        raise PermissionError("key revoked")
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
    if not current(rings, op["serial"], op["epoch"]):
        raise PermissionError("key revoked")
    return continue_operation(rings, opid)

def continue_operation(rings, opid):
    """Finish an already authorized operation within its original boundary.

    Recovery reuses the lease captured at operation start, so a revocation
    that happens after the destination link does not turn continuation into
    a new authorization request.
    """
    op = rings.data["operations"][opid]
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
