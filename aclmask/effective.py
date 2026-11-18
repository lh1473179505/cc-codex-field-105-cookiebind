def mask_for(entries):
    bits = set()
    for permissions in entries.values():
        bits.update(permissions.replace("-", ""))
    return "".join(bit if bit in bits else "-" for bit in "rwx")

def effective(obj, principal):
    supplied = obj["entries"].get(principal, "---")
    return "".join(s if s != "-" and m != "-" else "-"
                   for s, m in zip(supplied, obj["mask"]))
