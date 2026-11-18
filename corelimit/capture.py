from . import phases
from .ledger import Ledger

class SealFailure(RuntimeError):
    pass

def start(vault, capture, amount, owner):
    if capture in vault.data["captures"]:
        raise ValueError("duplicate capture")
    if vault.data["used"] + amount > vault.data["limit"]:
        raise MemoryError("core quota")
    vault.data["captures"][capture] = {"owner": owner, "phase": phases.REQUESTED,
                                       "epoch": vault.data["revocations"].get(owner, 0)}
    Ledger(vault.data).reserve(capture, amount)
    vault.data["captures"][capture]["phase"] = phases.RESERVED
    vault.save()
    return vault.data["captures"][capture]

def finish(vault, capture, fail=False):
    item = vault.data["captures"][capture]
    item["phase"] = phases.WRITTEN
    vault.data["cleanup"].append({"capture": capture, "done": False})
    vault.save()
    if fail:
        abort(vault, capture)
        raise SealFailure("sealer unavailable")
    item["phase"] = phases.SEALED
    Ledger(vault.data).release(capture)
    vault.data["cleanup"][-1]["done"] = True
    vault.save()

def abort(vault, capture):
    item = vault.data["captures"][capture]
    item["phase"] = phases.ABORTED
    Ledger(vault.data).release(capture)
    # The cleanup record deliberately remains available to the recovery scanner.
    vault.save()
