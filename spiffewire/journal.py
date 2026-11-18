class Journal:
    def capture(self, window, bundle):
        return {
            "format": "spiffe-1",
            "done": sorted(window.done),
            "domain": bundle.trust_domain,
            "generation": bundle.generation,
            "ids": sorted(bundle.ids),
        }

    def restore(self, state):
        from .batch import BatchWindow
        from .identity import Bundle
        window = BatchWindow()
        window.done = set(state["done"])
        bundle = Bundle()
        bundle.trust_domain = state["domain"]
        bundle.generation = state["generation"]
        bundle.ids = set(state["ids"])
        return window, bundle
