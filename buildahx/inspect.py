class LegacyInspect:
    def __init__(self, builder):
        self.builder = builder

    def image(self):
        manifest = self.builder.manifest.read()
        return {"schemaVersion": 1, "Layers": list(manifest["layers"])}

    def contains(self, layer):
        return layer in self.image()["Layers"]
