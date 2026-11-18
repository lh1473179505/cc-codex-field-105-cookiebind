class LegacyTargetClient:
    def __init__(self, release):
        self.release = release

    def fetch(self, path):
        alias = self.release.plan.aliases()[path]
        generation = self.release.plan.generation()
        if alias["generation"] != generation:
            raise RuntimeError(
                "target alias generation %s escaped snapshot %s" % (alias["generation"], generation)
            )
        return self.release.store.read(alias["digest"])

    def listing(self):
        return sorted(self.release.plan.aliases())
