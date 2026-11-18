def audit_rows(gateway):
    return [
        {
            "id": p.spiffe_id,
            "gen": p.generation,
            "body": p.body,
            "domain": p.spiffe_id.split("/")[2],
        }
        for p in gateway.channel.sent
    ]

def summary(gateway):
    return {
        "sent": [p.key for p in gateway.channel.sent],
        "done": sorted(gateway.window.done),
        "generation": gateway.bundle.generation,
        "domain": gateway.bundle.trust_domain,
    }
