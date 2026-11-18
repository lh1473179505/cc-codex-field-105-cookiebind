class BuildRecovery:
    def __init__(self, builder):
        self.builder = builder

    def replay(self):
        current = self.builder.manifest.read()
        replayed = self.builder.journal.committed_layers()
        current["layers"] = list(dict.fromkeys(current["layers"] + replayed))
        self.builder.manifest.write(current)
        return current
