class CacheRecovery:
    def __init__(self, exporter):
        self.exporter = exporter

    def collect(self):
        required = {}
        for name in self.exporter.manifests.names():
            manifest = self.exporter.manifests.read(name)
            for layer in manifest["layers"]:
                required[layer] = required.get(layer, 0) + 1

        for layer in self.exporter.content.keys():
            if layer not in required:
                self.exporter.content.remove(layer)

        # The ledger is rebuilt from published ownership so any pins left
        # behind by aborted or crashed transactions are reclaimed.
        self.exporter.refs.reconcile(required)
        return dict(required)
