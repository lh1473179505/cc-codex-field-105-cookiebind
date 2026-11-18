from .capture import abort
from . import phases

def recover(vault):
    cleaned = []
    for record in vault.data["cleanup"]:
        item = vault.data["captures"][record["capture"]]
        if record["done"] or item["phase"] == phases.SEALED:
            continue
        abort(vault, record["capture"])
        record["done"] = True
        cleaned.append(record["capture"])
    vault.save()
    return cleaned
