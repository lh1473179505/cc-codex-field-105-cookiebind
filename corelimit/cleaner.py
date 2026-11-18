from .capture import abort
from . import phases

def recover(vault):
    cleaned = []
    for record in vault.data["cleanup"]:
        item = vault.data["captures"][record["capture"]]
        if not record["done"] and item["phase"] != phases.SEALED:
            abort(vault, record["capture"])
            cleaned.append(record["capture"])
    vault.save()
    return cleaned
