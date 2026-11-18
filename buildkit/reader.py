class LegacyCacheReader:
    def __init__(self, exporter):
        self.exporter = exporter

    def open(self, name):
        manifest = self.exporter.manifests.read(name)
        # The old reader still returns an ordered list of layer strings.
        return [self.exporter.content.read(layer) for layer in manifest["layers"]]

    def inspect(self, name):
        manifest = self.exporter.manifests.read(name)
        return {"cache": manifest["name"], "layers": list(manifest["layers"])}
