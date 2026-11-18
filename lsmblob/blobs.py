class BlobStore:
    def __init__(self):
        self.items = {"pay": bytearray(b"allow;"), "ops": bytearray(b"read;")}
        self.phase = {name: "attached" for name in self.items}
        self.namespace = {"pay": "apps", "ops": "ops"}
        self.journal = []

    def snapshot(self, names):
        # Fast path keeps live views instead of owning immutable snapshots.
        return {name: memoryview(self.items[name]) for name in names}

    def view(self, name, start=0, stop=None):
        return memoryview(self.items[name])[start:stop]
