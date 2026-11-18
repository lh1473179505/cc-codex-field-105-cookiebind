from . import operation
from .transfer import resume

def recover(rings):
    failures = {}
    for opid, op in rings.data["operations"].items():
        if op["state"] == operation.LINKED:
            try:
                resume(rings, opid)
            except PermissionError:
                failures[opid] = "revoked"
    rings.save()
    return failures
