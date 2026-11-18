def route_view(router):
    return {
        "wire": list(router.wire.rows),
        "accepted": sorted(router.ledger.accepted),
        "epoch": router.trust.epoch,
    }

def legacy_pairs(router):
    # hidden contract: old collector wants (peer, payload) only
    return [(peer, payload) for peer, _epoch, payload in router.wire.rows]
