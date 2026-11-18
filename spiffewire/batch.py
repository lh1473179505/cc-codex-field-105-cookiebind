class BatchWindow:
    def __init__(self):
        self.open = {}
        self.done = set()

    def stage(self, packets, bundle):
        token = object()
        # BUG: bind identity at stage time only
        ok = [p for p in packets if bundle.allows(p.spiffe_id, p.generation) and p.key not in self.done]
        self.open[token] = {"packets": ok, "domain": bundle.trust_domain, "gen": bundle.generation}
        return token

    def flush(self, token, channel):
        item = self.open.pop(token)
        # BUG: mark done before all delivers succeed
        self.done.update(p.key for p in item["packets"])
        for packet in item["packets"]:
            channel.deliver(packet)
        return item
