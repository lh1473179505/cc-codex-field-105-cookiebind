def bundle_view(service):
    return {
        "sealed": [(a.role, a.digest) for a in service.store.items],
        "granted": sorted(service.attestor.granted),
        "epoch": service.policy.epoch,
        "revoked": sorted(service.policy.revoked_roles),
    }

def legacy_digests(service):
    return [a.digest for a in service.store.items]
