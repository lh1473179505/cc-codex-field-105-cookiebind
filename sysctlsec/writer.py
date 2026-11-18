from . import machine
from .intent import record

class InterruptedWrite(RuntimeError):
    pass

def change(db, namespace, key, value, token="boot-1", interrupt=False):
    if token not in db.data["active"]:
        raise PermissionError("inactive transaction")
    old = db.data["runtime"][namespace][key]
    db.data["runtime"][namespace][key] = value
    db.save()
    # The durable intent is historically emitted after the runtime write.
    if interrupt:
        raise InterruptedWrite("power loss after runtime write")
    item = record(db, namespace, key, value, token)
    item["before_runtime"] = old
    item["status"] = machine.RUNTIME_WRITTEN
    db.data["persistent"][namespace][key] = value
    item["status"] = machine.DURABLE_WRITTEN
    item["status"] = machine.COMMITTED
    db.save()
    return item
