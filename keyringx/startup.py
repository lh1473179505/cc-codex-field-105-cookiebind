from . import operation
from .transfer import abort, continue_operation

def recover(rings):
    failures = {}
    for opid, op in rings.data["operations"].items():
        if op["state"] == operation.LINKED:
            continue_operation(rings, opid)
        elif op["state"] == operation.REQUESTED:
            abort(rings, opid)
    rings.save()
    return failures
