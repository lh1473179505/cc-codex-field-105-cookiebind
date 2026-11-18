from . import phases

def revoke_owner(vault, owner):
    vault.data["revocations"][owner] = vault.data["revocations"].get(owner, 0) + 1
    vault.save()

def may_start(vault, owner, epoch):
    return epoch == vault.data["revocations"].get(owner, 0)
