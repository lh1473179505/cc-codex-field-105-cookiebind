from . import machine
from .intent import record

class InterruptedWrite(RuntimeError):
    pass

def change(db, namespace, key, value, token="boot-1", interrupt=False):
    if token not in db.data["active"]:
        raise PermissionError("inactive transaction")
    # Write-ahead intent: the recoverable previous value, desired value and
    # originating epoch must be durable before any runtime state changes.
    item = record(db, namespace, key, value, token)
    db.data["runtime"][namespace][key] = value
    item["status"] = machine.RUNTIME_WRITTEN
    db.save()
    # Power loss after the runtime layer changed: the write-ahead intent is
    # already durable, so recovery can always attribute and repair the change.
    if interrupt:
        raise InterruptedWrite("power loss after runtime write")
    db.data["persistent"][namespace][key] = value
    item["status"] = machine.DURABLE_WRITTEN
    item["status"] = machine.COMMITTED
    db.save()
    return item
